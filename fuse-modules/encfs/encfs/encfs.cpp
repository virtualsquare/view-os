/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
 * Modified 2006 Paolo Beverini
 * 
 * This program is free software; you can distribute it and/or modify it under 
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include "encfs.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statvfs.h>

#include <sys/types.h>
#ifdef linux
#include <sys/fsuid.h>
#endif

#ifdef HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#elif HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include <string>
#include <map>

#include "DirNode.h"
#include "MemoryPool.h"
#include "FileUtils.h"
#include <rlog/rlog.h>
#include <rlog/Error.h>

#ifndef MIN
#define MIN(a,b) (((a)<(b)) ? (a): (b))
#endif

using namespace std;
using namespace rlog;

struct EncfsFSContext
{
    void *reserved;//reserverd for main

    // for idle monitor
    bool running;
    pthread_t monitorThread;
    pthread_cond_t wakeupCond;
    pthread_mutex_t wakeupMutex;

    DirNode *FSRoot;
// if gPublicFilesystem is true, then try and make the filesystem behave like a
// normal multi-user filesystem (nodes are owned by the uid of the caller, etc)
    bool gPublicFilesystem;
    int oldStderr;
};


static RLogChannel *Info = DEF_CHANNEL("info", Log_Info);


/*
    The rLog messages below always print out encrypted filenames, not
    plaintext.  The reason is so that it isn't possible to leak information
    about the encrypted data through rlog interfaces.


    The purpose of this layer of code is to take the FUSE request and dispatch
    to the internal interfaces.  Any marshaling of arguments and return types
    can be done here.
*/

int encfs_getattr(const char *path, struct stat *stbuf)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	Ptr<FileNode> fnode = ec->FSRoot->lookupNode( path, "getattr" );

	rLog(Info, "getattr on %s", fnode->cipherName());

	res = fnode->getAttr( stbuf );
    } catch( rlog::Error &err )
    {
	rError("error caught in getattr");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
    try
    {
	int res = 0;
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	DirTraverse dt = ec->FSRoot->openDir( path );

	rLog(Info, "getdir on %s", ec->FSRoot->cipherPath(path).c_str());

	if(dt.valid())
	{
	    int fileType = 0;
	    ino_t inode = 0;

	    std::string name = dt.nextPlaintextName( &fileType, &inode );
	    while( !name.empty() )
	    {
		res = filler( h, name.c_str(), fileType, inode );

		if(res != 0)
		    break;

		name = dt.nextPlaintextName( &fileType, &inode );
	    } 
	} else
	{
	    rInfo("getdir request invalid, path: '%s'", path);
	}

	return res;
    } catch( rlog::Error &err )
    {
	rError("Error caught in getdir");
	err.log( _RLWarningChannel );
	return -EIO;
    }
}

int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	Ptr<FileNode> fnode = ec->FSRoot->lookupNode( path, "mknod" );

	rLog(Info, "mknod on %s, mode %i, dev %" PRIi64,
		fnode->cipherName(), mode, (int64_t)rdev);

	uid_t uid = 0;
	gid_t gid = 0;
	if(ec->gPublicFilesystem)
	{
	    uid = context->uid;
	    gid = context->gid;
	}
	res = fnode->mknod( mode, rdev, uid, gid );
    } catch( rlog::Error &err )
    {
	rError("error caught in mknod");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_mkdir(const char *path, mode_t mode)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	uid_t uid = 0;
	gid_t gid = 0;
	if(ec->gPublicFilesystem)
	{
	    uid = context->uid;
	    gid = context->gid;
	}
	res = ec->FSRoot->mkdir( path, mode, uid, gid );
    } catch( rlog::Error &err )
    {
	rError("error caught in mkdir");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_unlink(const char *path)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	// let DirNode handle it atomically so that it can handle race
	// conditions
	res = ec->FSRoot->unlink( path );
    } catch( rlog::Error &err )
    {
	rError("error caught in unlink");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_rmdir(const char *path)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "rmdir %s", cyName.c_str());

	res = rmdir( cyName.c_str() );
	if(res == -1)
	{
	    int eno = errno;
	    rInfo("unlink error: %s", strerror(eno));
	    res = -eno;
	} else
	    res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in rmdir");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_readlink(const char *path, char *buf, size_t size)
{
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );
	
	rLog(Info, "readlink %s", cyName.c_str());

	int res = ::readlink( cyName.c_str(), buf, size-1 );

	if(res == -1)
	    return -errno;

	buf[res] = '\0'; // ensure null termination
	string decodedName;
	try
	{
	    decodedName = ec->FSRoot->plainPath( buf );
	} catch(...) { }

	if(!decodedName.empty())
	{
	    strncpy(buf, decodedName.c_str(), size-1);
	    buf[size-1] = '\0';

	    return 0;
	} else
	{
	    rWarning("Error decoding link");
	    return -1;
	}
    } catch( rlog::Error &err )
    {
	rError("error caught in rmdir");
	err.log( _RLWarningChannel );
	return -EIO;
    }
}

int encfs_symlink(const char *from, const char *to)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	// allow fully qualified names in symbolic links.
	string fromCName = ec->FSRoot->relativeCipherPath( from );
	string toCName = ec->FSRoot->cipherPath( to );
	
	rLog(Info, "symlink %s -> %s", fromCName.c_str(), toCName.c_str());

	// use setfsuid / setfsgid so that the new link will be owned by the
	// uid/gid provided by the fuse_context.
	int olduid = -1;
	int oldgid = -1;
	if(ec->gPublicFilesystem)
	{
	    olduid = setfsuid( context->uid );
	    oldgid = setfsgid( context->gid );
	}
	res = ::symlink( fromCName.c_str(), toCName.c_str() );
	if(olduid >= 0)
	    setfsuid( olduid );
	if(oldgid >= 0)
	    setfsgid( oldgid );

	if(res == -1)
	    res = -errno;
	else
	    res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in symlink");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_link(const char *from, const char *to)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	res = ec->FSRoot->link( from, to );
    } catch( rlog::Error &err )
    {
	rError("error caught in link");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_rename(const char *from, const char *to)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	res = ec->FSRoot->rename( from, to );
    } catch( rlog::Error &err )
    {
	rError("error caught in rename");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_chmod(const char *path, mode_t mode)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "chmod %s, mode %i", cyName.c_str(), mode);

	res = chmod( cyName.c_str(), mode );
	if(res == -1)
	{
	    int eno = errno;
	    rInfo("chmod error: %s", strerror(eno));
	    res = -eno;
	} else
	    res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in chmod");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );
	
	rLog(Info, "chown %s, uid %i, gid %i", cyName.c_str(), uid, gid);

	res = lchown( cyName.c_str(), uid, gid );
	if(res == -1)
	    res = -errno;
	else
	    res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in chown");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_truncate(const char *path, off_t size)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	Ptr<FileNode> fnode = ec->FSRoot->lookupNode( path, "truncate" );
       
	rLog(Info, "truncate %s", fnode->cipherName());
	
	res = fnode->truncate( size );
    } catch( rlog::Error &err )
    {
	rError("error caught in truncate");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_utime(const char *path, struct utimbuf *buf)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );
	
	rLog(Info, "utime %s", cyName.c_str());

	res = utime( cyName.c_str(), buf);
	if(res == -1)
	{
	    int eno = errno;
	    rInfo("utime error: %s", strerror(eno));
	    res = -eno;
	} else
	    res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in utime");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_open(const char *path, struct fuse_file_info *file)
{
    int res = -EIO;
    Ptr<FileNode> fnode;

    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	fnode = ec->FSRoot->openNode( path, "open", file->flags, &res );

	if(!fnode.isNull())
	{
	    rLog(Info, "encfs_open for %s, flags %i", fnode->cipherName(), 
		    file->flags);

	    if( res >= 0 )
	    {
		file->fh = res; // store file handle
		res = 0; // success is 0
	    }
	}
    } catch( rlog::Error &err )
    {
	rError("error caught in open");
	err.log( _RLWarningChannel );
    }

    return res;
}

int encfs_flush(const char *path, struct fuse_file_info *file)
{
    (void)path;
    (void)file;
    return 0; // could also return -38 (function not implemented)..
}

/*
Note: This is advisory -- it might benefit us to keep file nodes around for a
bit after they are released just in case they are reopened soon.  But that
requires a cache layer.
 */
int encfs_release(const char *path, struct fuse_file_info *file)
{
    (void)file;
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	ec->FSRoot->release( path );

	res = 0;
    } catch( rlog::Error &err )
    {
	rError("error caught in release");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *file)
{
    (void)file;
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	Ptr<FileNode> fnode = ec->FSRoot->lookupNode( path, "read" );

	rLog(Info, "read %s, offset %" PRIi64 ", size %i",
		fnode->cipherName(), offset, (int)size);

	ssize_t rdSz = fnode->read( offset, (unsigned char *)buf, size );

	res = rdSz;
    } catch( rlog::Error &err )
    {
	rError("error caught in read: %s", err.message());
	rError("read offset %" PRIi64 ", %i", offset, (int)size);
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_fsync(const char *path, int dataSync,
	struct fuse_file_info *file)
{
    (void)path;
#ifndef linux
    (void)dataSync;
#endif

    int res = -EIO;
    try
    {
#ifdef linux
	if(dataSync == 0)
#endif
	    res = fsync( file->fh );
#ifdef linux
	else
	    res = fdatasync( file->fh );
#endif
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in fsync");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *file)
{
    (void)file;
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	Ptr<FileNode> fnode = ec->FSRoot->lookupNode( path, "write" );

	rLog(Info, "write %s, offset %" PRIi64 ", size %i",
		fnode->cipherName(), offset, (int)size);

	if(fnode->write( offset, (unsigned char *)buf, size ))
	    res = size;
	else
	    rInfo("encfs_write: write failed");
    } catch( rlog::Error &err )
    {
	rError("error caught in write");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_statfs(const char *path, struct statvfs *st)
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	(void)path; // path should always be '/' for now..
	rAssert( st != NULL );
	string cyName = ec->FSRoot->rootDirectory();

	rLog(Info, "doing statfs of %s", cyName.c_str());
	res = statvfs( cyName.c_str(), st );
	if(!res) 
	{
	    // adjust maximum name length..
	    st->f_namemax     = 6 * (st->f_namemax - 2) / 8; // approx..
	}
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in statfs");
	err.log( _RLWarningChannel );
    }
    return res;
}

#ifdef HAVE_XATTR
int encfs_setxattr( const char *path, const char *name,
	const char *value, size_t size, int flags )
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "setxattr %s", cyName.c_str());

	res = ::setxattr( cyName.c_str(), name, value, size, flags );
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in setxattr");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_getxattr( const char *path, const char *name,
	char *value, size_t size )
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "getxattr %s", cyName.c_str());

	res = ::getxattr( cyName.c_str(), name, value, size );
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in getxattr");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_listxattr( const char *path, char *list, size_t size )
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "listxattr %s", cyName.c_str());

	res = ::listxattr( cyName.c_str(), list, size );
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in listxattr");
	err.log( _RLWarningChannel );
    }
    return res;
}

int encfs_removexattr( const char *path, const char *name )
{
    int res = -EIO;
    try
    {
        struct fuse_context *context=fuse_get_context();
        struct EncfsFSContext *ec=(struct EncfsFSContext *)context->private_data;

	string cyName = ec->FSRoot->cipherPath( path );

	rLog(Info, "removexattr %s", cyName.c_str());

	res = ::removexattr( cyName.c_str(), name );
	if(res == -1)
	    res = -errno;
    } catch( rlog::Error &err )
    {
	rError("error caught in removexattr");
	err.log( _RLWarningChannel );
    }
    return res;
}
#endif // HAVE_XATTR

