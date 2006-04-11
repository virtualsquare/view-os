/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003-2004, Valient Gough
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

// Include encfs first, because we need to include fuse.h before any inclusion
// of sys/stat.h or other system headers (to be safe)
#include "encfs.h"

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef linux
#include <sys/fsuid.h>
#endif

#include "config.h"

#include "FileNode.h"
#include "Cipher.h"
#include "CipherFileIO.h"
#include "RawFileIO.h"
#include "MACFileIO.h"
#include "MACFileIOCompat.h"
#include "DirNode.h"

#include "FileIO.h"
#include "MemoryPool.h"
#include "Mutex.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

using namespace std;
using namespace rel;
using namespace rlog;

/*
   TODO: locking at the FileNode level is inefficient, since this precludes
   multiple IO operations from going on concurrently within the same file.

   There is no reason why simultainous reads cannot be satisfied, or why one
   read has to wait for the decoding of the previous read before it can be
   sent to the IO subsystem!
*/

static RLogChannel *Info = DEF_CHANNEL("info/FileNode", Log_Info);

FileNode::FileNode(DirNode *parent_, 
	int fsSubVersion,
	const char *plaintextName_, const char *cipherName_, 
	const Ptr<Cipher> &dataCipher, const CipherKey &key, int blockSize,
	int blockMACBytes, int blockMACRandBytes, bool uniqueIV,
	bool externalIVChaining_, bool forceDecode )
{
    pthread_mutex_init( &mutex, 0 );
    
    Lock _lock( mutex );

    refCnt = 1;
    this->_pname = plaintextName_;
    this->_cname = cipherName_;
    this->parent = parent_;
    this->retainCount = 0;
    this->externalIVChaining = externalIVChaining_;

    // chain RawFileIO & CipherFileIO
    Ptr<FileIO> rawIO( new RawFileIO( _cname ) );
    io = Ptr<FileIO>( 
	    new CipherFileIO( rawIO, dataCipher, key, blockSize, uniqueIV));
    if(blockMACBytes)
    {
	// filesystems from before 20040813 had potential problems with the MAC
	// block implementation.. But I'd like to be able to read old
	// filesystems, even if there are better options when creating new
	// ones....
	if(fsSubVersion >= 20040813)
	{
	    io = Ptr<FileIO>(new MACFileIO(io, dataCipher, key, 
	    		blockSize,blockMACBytes,blockMACRandBytes,forceDecode));
	} else
	{
	    // backward compatible code..
	    static bool warnOnce = false;
	    if(!warnOnce)
	    {
		rWarning("Using backward compatibility mode for "
			"MAC block algorithm");
		warnOnce = true;
	    }
	    io = Ptr<FileIO>(new MACFileIOCompat(io, dataCipher, key, 
	    		blockSize,blockMACBytes,blockMACRandBytes,forceDecode));
	}
    }
}

FileNode::~FileNode()
{
    // FileNode mutex should be locked before the destructor is called
    //pthread_mutex_lock( &mutex );

    if( refCnt != 0 )
	rError("FileNode destroyed with refCnt %i", refCnt );
    if( retainCount != 0 )
	rError("FileNode destroyed with retain count %i", retainCount);
    _pname.assign( _pname.length(), '\0' );
    _cname.assign( _cname.length(), '\0' );
    io.reset();

    pthread_mutex_unlock( &mutex );
    pthread_mutex_destroy( &mutex );
}

int FileNode::incRef()
{
    Lock _lock( mutex );
    return ++refCnt;
}

int FileNode::incRetain()
{
    Lock _lock( mutex );
    return ++retainCount;
}

const char *FileNode::cipherName() const
{
    return _cname.c_str();
}

const char *FileNode::plaintextName() const
{
    return _pname.c_str();
}

static bool setIV(const Ptr<FileIO> &io, uint64_t iv)
{
    struct stat stbuf;
    if((io->getAttr(&stbuf) < 0) || S_ISREG(stbuf.st_mode))
	return io->setIV( iv );
    else
	return true;
}

bool FileNode::setName( const char *plaintextName_, const char *cipherName_,
	uint64_t iv, bool setIVFirst )
{
    // we're called by processes that have locked us... ugly I know..
    //Lock _lock( mutex );
    rDebug("calling setIV on %s", cipherName_);
    if(setIVFirst)
    {
	if(externalIVChaining && !setIV(io, iv))
	    return false;

	// now change the name..
	if(plaintextName_)
	    this->_pname = plaintextName_;
	if(cipherName_)
	{
	    this->_cname = cipherName_;
	    io->setFileName( cipherName_ );
	}
    } else
    {
	std::string oldPName = _pname;
	std::string oldCName = _cname;

	if(plaintextName_)
	    this->_pname = plaintextName_;
	if(cipherName_)
	{
	    this->_cname = cipherName_;
	    io->setFileName( cipherName_ );
	}

	if(externalIVChaining && !setIV(io, iv))
	{
	    _pname = oldPName;
	    _cname = oldCName;
	    return false;
	}
    }

    return true;
}

int FileNode::mknod(mode_t mode, dev_t rdev, uid_t uid, gid_t gid)
{
    Lock _lock( mutex );
    rAssert( refCnt > 0 );

    if( retainCount != 0 )
    {
	rWarning("mknod attempted on file %s , retain count %i",
		_cname.c_str(), retainCount);
    }

    int res;
    int olduid = -1;
    int oldgid = -1;
    if(uid != 0)
	olduid = setfsuid( uid );
    if(gid != 0)
	oldgid = setfsgid( gid );

    /*
     * cf. xmp_mknod() in fusexmp.c
     * The regular file stuff could be stripped off if there
     * were a create method (advised to have)
     */
    if (S_ISREG( mode )) {
        res = ::open( _cname.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode );
        if (res >= 0)
            res = ::close( res );
    } else if (S_ISFIFO( mode ))
        res = ::mkfifo( _cname.c_str(), mode );
    else
        res = ::mknod( _cname.c_str(), mode, rdev );

    if(olduid >= 0)
	setfsuid( olduid );
    if(oldgid >= 0)
	setfsgid( oldgid );

    if(res == -1)
    {
	int eno = errno;
	if( retainCount != 0 )
	    rWarning("mknod error: %s", strerror(eno));
	else
	    rDebug("mknod error: %s", strerror(eno));
	res = -eno;
    }

    return res;
}

int FileNode::open(int flags) const
{
    Lock _lock( mutex );
    rAssert( refCnt > 0 );

    int res = io->open( flags );
    return res;
}

int FileNode::getAttr(struct stat *stbuf) const
{
    Lock _lock( mutex );
    rAssert( refCnt > 0 );

    int res = io->getAttr( stbuf );
    return res;
}

off_t FileNode::getSize() const
{
    Lock _lock( mutex );
    rAssert( refCnt > 0 );

    int res = io->getSize();
    return res;
}

ssize_t FileNode::read( off_t offset, unsigned char *data, ssize_t size ) const
{
    IORequest req;
    req.offset = offset;
    req.dataLen = size;
    req.data = data;

    Lock _lock( mutex );
    rAssert( refCnt > 0 );
    rAssert( retainCount > 0 );

    return io->read( req );
}

bool FileNode::write(off_t offset, unsigned char *data, ssize_t size)
{
    rLog(Info, "FileNode::write offset %" PRIi64 ", data size %i",
	    offset, (int)size);

    IORequest req;
    req.offset = offset;
    req.dataLen = size;
    req.data = data;
    
    Lock _lock( mutex );
    rAssert( refCnt > 0 );
    rAssert( retainCount > 0 );

    return io->write( req );
}

int FileNode::truncate( off_t size )
{
    Lock _lock( mutex );
    rAssert( refCnt > 0 );

    return io->truncate( size );
}

