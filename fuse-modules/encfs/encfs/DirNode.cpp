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

#include "encfs.h"

#include "DirNode.h"
#include "FileUtils.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#ifdef linux
#include <sys/fsuid.h>
#endif

#include "Cipher.h"
#include "Mutex.h"
#include <rlog/rlog.h>
#include <rlog/Error.h>

#include <iostream>

using namespace std;
using namespace rel;
using namespace rlog;

static RLogChannel *Info = DEF_CHANNEL( "info/DirNode", Log_Info );

// the usefullness of the cache drops dramatically after 1 or 2 nodes..
const int RecentNodeCacheSize = 3;

#define CACHE_STATS 0

#if CACHE_STATS

static int cacheHits[RecentNodeCacheSize] = {0};
static int cacheMiss = 0;

#endif

/*
    If REQUEST_HISTORY is enabled, then we store a bunch of extra data about
    what happened with a file.  It is only useful for debugging, and probably
    only for very particular uses..
*/
#define REQUEST_HISTORY 0

/*
    If USE_CIPHERTEXT_KEYS is defined, then internal node data is stored
    indexed by ciphertext name rather then plaintext name.

    Indexing by plaintext name is faster, but indexing by ciphertext names
    might reduce the possibility of plaintext names being left in memory..

    Perhaps this can be a runtime option on a per-filesystem basis..
*/
#ifdef USE_CIPHERTEXT_KEYS
#   define HASHKEY(KEY) naming->encodePath(KEY).c_str()
#else
#   define HASHKEY(KEY) KEY
#endif

#define ATIME_ATOMIC_UPDATE \
if(inactivityTimer) \
{ \
    Lock _lock( mutex ); \
    lastAccess = time(0); \
}



#if REQUEST_HISTORY
/*
    For debugging purposes.  This keeps track of each request type for every
    file.  Lots of data..
*/
struct RequestHistory
{
    list< string > requestor;
};

static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;
map<string, RequestHistory*> gRequestHistory;

static void addHistory( const char *plainName, const char *info )
{
    pthread_mutex_lock( &gMutex );
    map<string,RequestHistory*>::iterator it = gRequestHistory.find(plainName);
    if(it != gRequestHistory.end())
    {
	it->second->requestor.push_back( string( info ) );
    } else
    {
	RequestHistory *rq = new RequestHistory;
	rq->requestor.push_back( string( info ) );
	gRequestHistory.insert( make_pair( string(plainName), rq ));
    }
    pthread_mutex_unlock( &gMutex );
}

static
void showHistory( const char *name )
{
    pthread_mutex_lock( &gMutex );
    map<string, RequestHistory*>::iterator it = gRequestHistory.find( name );

    if(it != gRequestHistory.end())
    {
	cout << "request history for filename " << name << ":\n";
	list<string>::iterator lit = it->second->requestor.begin();
	for(; lit != it->second->requestor.end(); ++lit)
	{
	    cout << "    requested by \"" << (*lit) << "\"\n";
	}
    } else
    {
	cout << "no history for filename " << name << endl;
    }

    pthread_mutex_unlock( &gMutex );
}
#endif



DirTraverse::DirTraverse(DIR *_dirPtr, uint64_t _iv, const NameIO *_naming)
    : LinkedOwner()
    , dir( _dirPtr )
    , iv( _iv )
    , naming( _naming )
{
}

DirTraverse::DirTraverse(const DirTraverse &src)
    : LinkedOwner()
    , dir( src.dir )
    , iv( src.iv )
    , naming( src.naming )
{
    shareOwnership( &src );
}

DirTraverse &DirTraverse::operator = (const DirTraverse &src)
{
    if(dir != src.dir)
    {
	if(dropOwnership() && dir)
	    ::closedir( (DIR*)dir );

	shareOwnership( &src );

	dir = src.dir;
	iv = src.iv;
	naming = src.naming;
    }
    
    return *this;
}

DirTraverse::~DirTraverse()
{
    if(dropOwnership())
    {
	if(dir)
	    ::closedir( (DIR*)dir );
	dir = NULL;
	iv = 0;
	naming = 0;
    }
}

static
bool _nextName(struct dirent *&de, DIR *dir, int *fileType, ino_t *inode)
{
    de = ::readdir( dir );

    if(de)
    {
	if(fileType)
	{
#if defined(_DIRENT_HAVE_D_TYPE) || defined(__FreeBSD__)
	    *fileType = de->d_type;
#else
#warning "struct dirent.d_type not supported"
	    *fileType = 0;
#endif
	}
	if(inode)
	    *inode = de->d_ino;
	return true;
    } else
    {
	if(fileType)
	    *fileType = 0;
	return false;
    }
}


std::string DirTraverse::nextPlaintextName(int *fileType, ino_t *inode)
{
    struct dirent *de=0;
    while(_nextName(de, dir, fileType, inode))
    {
	try
	{
	    uint64_t localIv = iv;
	    return naming->decodePath( de->d_name, &localIv );
	} catch ( rlog::Error &ex )
	{
	    // .. .problem decoding, ignore it and continue on to next name..
	    rDebug("error decoding filename: %s", de->d_name);
	}
    }

    return string();
}

std::string DirTraverse::nextInvalid()
{
    struct dirent *de=0;
    // find the first name which produces a decoding error...
    while(_nextName(de, dir, (int*)0, (ino_t*)0))
    {
	try
	{
	    uint64_t localIv = iv;
	    naming->decodePath( de->d_name, &localIv );
	    continue;
	} catch( rlog::Error &ex )
	{
	    return string( de->d_name );
	}
    }

    return string();
}

DirNode::DirNode(const string &sourceDir, const Ptr<Config> &_config)
{
    pthread_mutex_init( &mutex, 0 );
    
    Lock _lock( mutex );

    rootDir = sourceDir;
    config = _config;

    // make sure rootDir ends in '/', so that we can form a path by appending
    // the rest..
    if( rootDir[ rootDir.length()-1 ] != '/' )
	rootDir.append( 1, '/');

    naming = config->nameCoding.get();
    inactivityTimer = config->inactivityTimer;

    lastAccess = inactivityTimer ? time(0) : 0;

    recentNodes.resize( RecentNodeCacheSize, (FileNode*)0 );
    nextCacheLoc = 0;
}

DirNode::~DirNode()
{
#if CACHE_STATS
    cerr << "cache stats: " << cacheMiss << " misses, hits by age:\n";
#endif
    for(int i=0; i<RecentNodeCacheSize; ++i)
    {
#if CACHE_STATS
	cerr << "age " << i << " : " << cacheHits[i] << " hits\n";
#endif
	if(recentNodes[i] != NULL)
	{
	    FileNodeDestructor( recentNodes[i] );
	    recentNodes[i] = NULL;
	}
    }

    if(!openFiles.empty())
    {
	rError("Leaked FileNodes: %i", (int)openFiles.size());
	CacheMap::iterator it = openFiles.begin();
	for(; it!= openFiles.end(); ++it)
	{
	    rError("Leaked node: %s", it->second->cipherName());
	}
    }
}

bool
DirNode::hasDirectoryNameDependency() const
{
    return naming ? naming->getChainedNameIV() : false;
}

string
DirNode::rootDirectory()
{
    // don't update last access here, otherwise 'du' would cause lastAccess to
    // be reset.
    // chop off '/' terminator from root dir.
    return string( rootDir, 0, rootDir.length()-1 );
}

string 
DirNode::cipherPath( const char *plaintextPath )
{
    ATIME_ATOMIC_UPDATE

    return rootDir + naming->encodePath( plaintextPath );
}

string
DirNode::plainPath( const char *cipherPath_ )
{
    ATIME_ATOMIC_UPDATE

    try
    {
	if( !strncmp( cipherPath_, rootDir.c_str(), 
		    rootDir.length() ) )
	{
	    return naming->decodePath( cipherPath_ + rootDir.length() );
	} else
	{
	    if ( cipherPath_[0] == '+' )
	    {
		// decode as fully qualified path
		return string("/") + naming->decodeName( cipherPath_+1, 
			strlen(cipherPath_+1) );
	    } else
	    {
		return naming->decodePath( cipherPath_ );
	    }
	}

    } catch( rlog::Error &err )
    {
	rError("decode err: %s", err.message());
	err.log( _RLWarningChannel );

	return string();
    }
}

string
DirNode::relativeCipherPath( const char *plaintextPath )
{
    ATIME_ATOMIC_UPDATE

    try
    {
	if(plaintextPath[0] == '/')
	{
	    // mark with '+' to indicate special decoding..
	    return string("+") + naming->encodeName(plaintextPath+1, 
		    strlen(plaintextPath+1));
	} else
	{
	    return naming->encodePath( plaintextPath );
	}
    } catch( rlog::Error &err )
    {
	rError("encode err: %s", err.message());
	err.log( _RLWarningChannel );

	return string();
    }
}

DirTraverse DirNode::openDir(const char *plaintextPath)
{
    ATIME_ATOMIC_UPDATE

    string cyName = rootDir + naming->encodePath( plaintextPath );
    //rDebug("openDir on %s", cyName.c_str() );

    DIR *dp = ::opendir( cyName.c_str() );
    if(!dp)
    {
	rDebug("opendir error %s", strerror(errno));
	return DirTraverse( 0, 0, 0 );
    } else
    {
	uint64_t iv = 0;
	// if we're using chained IV mode, then compute the IV at this
	// directory level..
	try
	{
	    if( naming->getChainedNameIV() )
		naming->encodePath( plaintextPath, &iv );
	} catch( rlog::Error &err )
	{
	    rError("encode err: %s", err.message());
	    err.log( _RLWarningChannel );
	}
	return DirTraverse( dp, iv, naming );
    }
}

bool DirNode::genRenameList( list<RenameEl> &renameList, const char *fromP,
	const char *toP )
{
    uint64_t fromIV = 0, toIV = 0;

    // compute the IV for both paths
    string fromCPart = naming->encodePath( fromP, &fromIV );
    string toCPart = naming->encodePath( toP, &toIV );

    // where the files live before the rename..
    string sourcePath = rootDir + fromCPart;

    // ok..... we wish it was so simple.. should almost never happen
    if(fromIV == toIV)
	return true;

    // generate the real destination path, where we expect to find the files..
    rDebug("opendir %s", sourcePath.c_str() );
    DIR *dir = opendir( sourcePath.c_str() );
    if(dir == NULL)
	return false;
    
    struct dirent *de = NULL;
    while((de = ::readdir( dir )) != NULL)
    {
	// decode the name using the oldIV
	uint64_t localIV = fromIV;
	string plainName;
	
	try
	{
	    plainName = naming->decodePath( de->d_name, &localIV );
	} catch( rlog::Error &ex )
	{
	    // if filename can't be decoded, then ignore it..
	    continue;
	}

	// any error in the following will trigger a rename failure.
	try
	{
	    // re-encode using the new IV..
	    localIV = toIV;
	    string newName = naming->encodePath( plainName.c_str(), &localIV );
	
    	    // store rename information..
    	    string oldFull = sourcePath + '/' + de->d_name;
    	    string newFull = sourcePath + '/' + newName;

	    RenameEl ren;
	    ren.oldCName = oldFull;
	    ren.newCName = newFull;
	    ren.oldPName = string(fromP) + '/' + plainName;
	    ren.newPName = string(toP) + '/' + plainName;
	    
	    bool isDir;
#if defined(_DIRENT_HAVE_D_TYPE)
	    if(de->d_type != DT_UNKNOWN)
	    {
		isDir = (de->d_type == DT_DIR);
	    } else
#endif
	    {
		isDir = isDirectory( oldFull.c_str() );
	    }

	    ren.isDirectory = isDir;

	    if(isDir)
	    {
		// recurse..  We want to add subdirectory elements before the
		// parent, as that is the logical rename order..
		if(!genRenameList( renameList, 
			    ren.oldPName.c_str(), 
			    ren.newPName.c_str()))
		{
		    closedir( dir );
		    return false;
		}
	    }

	    rDebug("adding file %s to rename list",
		    oldFull.c_str());

	    renameList.push_back( ren );

	} catch( rlog::Error &err )
	{
	    // We can't convert this name, because we don't have a valid IV for
	    // it (or perhaps a valid key).. It will be inaccessible..
	    rWarning("Aborting rename: error on file: %s",
		    fromCPart.append(1, '/').append(de->d_name).c_str());
	    err.log( _RLDebugChannel );

	    // abort.. Err on the side of safety and disallow rename, rather
	    // then loosing files..
	    closedir( dir );
	    return false;
	}
    }
    closedir( dir );
    return true;
}

void DirNode::undoRename( list<RenameEl> &renameList,
	list<RenameEl>::const_iterator &undoEnd)
{
    rDebug("in undoRename");

    if(undoEnd == renameList.begin())
    {
	rDebug("nothing to undo");
	return; // nothing to undo
    }

    // list has to be processed backwards, otherwise we may rename directories
    // and directory contents in the wrong order!
    int undoCount = 0;
    list<RenameEl>::const_iterator it = undoEnd;

    while( it != renameList.begin() )
    {
	--it;

	rDebug("undo: renaming %s -> %s", 
		it->newCName.c_str(), it->oldCName.c_str());

	::rename( it->newCName.c_str(), it->oldCName.c_str() );
	try
	{
	    renameNode( it->newPName.c_str(), it->oldPName.c_str(), false );
	} catch( rlog::Error &err )
	{
	    err.log( _RLWarningChannel );
	    // continue on anyway...
	}
	++undoCount;
    };
    
    rWarning("Undo rename count: %i", undoCount);
}

void DirNode::cleanList( list<RenameEl> &renameList )
{
    // now we've potentially got a bunch of decoded filenames sitting in
    // memory..  do a little cleanup before leaving..
    list<RenameEl>::iterator it;
    for(it = renameList.begin(); it != renameList.end(); ++it)
    {
	it->oldPName.assign( it->oldPName.size(), ' ' );
	it->newPName.assign( it->newPName.size(), ' ' );
    }
}

/*
    A bit of a pain.. If a directory is renamed in a filesystem with
    directory initialization vector chaining, then we have to recursively
    rename every descendent of this directory, as all initialization vectors
    will have changed..
*/
bool DirNode::recursiveRename( const char *fromP, const char *toP )
{
    // Do the rename in two stages to avoid chasing our tail
    // Undo everything if we encounter an error!
    list<RenameEl> renameList;
    bool ok = true;
    if(!genRenameList( renameList, fromP, toP ))
    {
	rWarning("Error during generation of recursive rename list");
	cleanList( renameList );
	ok = false;
    } else
    {
	list<RenameEl>::const_iterator it = renameList.begin();

	try
	{
	    // start renaming, keeping track of an undo point in case we have to
	    // stop
	    for(it = renameList.begin(); it != renameList.end(); ++it)
	    {
		// backing store rename.
		rDebug("renaming %s -> %s",
			it->oldCName.c_str(), it->newCName.c_str());

		// internal node rename..
		renameNode( it->oldPName.c_str(), it->newPName.c_str() );

		// rename on disk..
		if(::rename( it->oldCName.c_str(), it->newCName.c_str() ) == -1)
		{
		    rWarning("Error renaming %s: %s",
			    it->oldCName.c_str(), strerror( errno ));
		    renameNode( it->newPName.c_str(), 
			    it->oldPName.c_str(), false );
		    ok = false;
		    break;
		}
	    }
	} catch( rlog::Error &err )
	{
	    err.log( _RLWarningChannel );
	    ok = false;
	}

	if(!ok)
	    undoRename( renameList, it );
	cleanList( renameList );
    }
    return ok;
}

int DirNode::mkdir(const char *plaintextPath, mode_t mode, 
	uid_t uid, gid_t gid)
{
    string cyName = rootDir + naming->encodePath( plaintextPath );
    rAssert( !cyName.empty() );

    rLog( Info, "mkdir on %s", cyName.c_str() );

    // if uid or gid are set, then that should be the directory owner
    int olduid = -1;
    int oldgid = -1;
    if(uid != 0)
	olduid = setfsuid( uid );
    if(gid != 0)
	oldgid = setfsgid( gid );

    int res = ::mkdir( cyName.c_str(), mode );

    if(olduid >= 0)
	setfsuid( olduid );
    if(oldgid >= 0)
	setfsgid( oldgid );

    if(res == -1)
    {
	int eno = errno;
	rWarning("mkdir error on %s mode %i: %s", cyName.c_str(), 
		mode, strerror(eno));
	res = -eno;
    } else
	res = 0;

    return res;
}

int 
DirNode::rename( const char *fromPlaintext, const char *toPlaintext )
{
    Lock _lock( mutex );

    string fromCName = rootDir + naming->encodePath( fromPlaintext );
    string toCName = rootDir + naming->encodePath( toPlaintext );
    rAssert( !fromCName.empty() );
    rAssert( !toCName.empty() );
    
    rLog( Info, "rename %s -> %s", fromCName.c_str(), toCName.c_str() );
   
    bool inMap = false;
    FileNode *toNode = findNode( toPlaintext, &inMap );

    if(toNode && inMap != false)
    {
	rError("Error, attempting to rename %s over existing open file %s !",
		fromCName.c_str(), toCName.c_str() );
	return -EACCES;
    }

    bool didRecursiveRename = false;
    if( hasDirectoryNameDependency() && isDirectory( fromCName.c_str() ))
    {
	rLog( Info, "recursive rename begin" );
	if(! recursiveRename( fromPlaintext, toPlaintext ))
	{
	    rWarning("rename aborted");
	    return -EACCES;
	}
	rLog( Info, "recursive rename end" );
	didRecursiveRename = true;
    }

    int res = 0;
    try
    {
	renameNode( fromPlaintext, toPlaintext );
	res = ::rename( fromCName.c_str(), toCName.c_str() );

	if(res == -1)
	{
	    // undo
	    res = -errno;
	    renameNode( toPlaintext, fromPlaintext, false );
	}
    } catch( rlog::Error &err )
    {
	// exception from renameNode, just show the error and continue..
	err.log( _RLWarningChannel );
	res = -EIO;
    }
   
    if(res != 0)
    {
	rLog( Info, "rename failed: %s", strerror( errno ));
	res = -errno;
    }

    return res;
}

int DirNode::link( const char *from, const char *to )
{
    Lock _lock( mutex );

    string fromCName = rootDir + naming->encodePath( from );
    string toCName = rootDir + naming->encodePath( to );

    rAssert( !fromCName.empty() );
    rAssert( !toCName.empty() );

    rLog(Info, "link %s -> %s", fromCName.c_str(), toCName.c_str());

    int res = -EPERM;
    if( config->externalIVChaining )
    {
	rLog(Info, "hard links not supported with external IV chaining!");
    } else
    {
	res = ::link( fromCName.c_str(), toCName.c_str() );
	if(res == -1)
	    res = -errno;
	else
	    res = 0;
    }

    return res;
}

bool 
DirNode::hasOpenFiles()
{
    Lock _lock( mutex );
    bool result = !openFiles.empty();

    return result;
}

string
DirNode::openFileList()
{
    Lock _lock( mutex );

    string result;

    CacheMap::const_iterator it = openFiles.begin();
    CacheMap::const_iterator end = openFiles.end();
    for(; it != end; ++it)
    {
	result += it->second->cipherName();
	result += "\n";
    }

    return result;
}

int
DirNode::idleSeconds()
{
    if(inactivityTimer)
    {
	Lock _lock( mutex );
	time_t current = time(0);
	return int( current - lastAccess );
    } else
	return 0;
}

void FileNodeDestructor( FileNode *fnode )
{
    if(fnode == NULL)
	return;

    Lock fnodeLock( fnode->mutex );

    rLog( Info, "in FileNodeDestructor for %s (refcount %i)",
	    fnode->cipherName(), fnode->refCnt);

    if( fnode->refCnt <= 0 )
	rError("Error, fnode %s refcount = %i before release",
		fnode->cipherName(), fnode->refCnt );

    // don't destroy nodes which are in the cache.  Only release() removes from
    // the cache, and then the node can be destroyed..
    if( (--fnode->refCnt == 0) && (fnode->retainCount == 0) )
    {
	rLog( Info, "destroying FNode %s", fnode->cipherName());

	// mutex held going into destructor..
	fnodeLock.leave();
	delete fnode;
    }
}

/*
    Release should be called the same number of times as openNode()
*/
void
DirNode::release( const char *plaintextPath )
{
#if REQUEST_HISTORY
    addHistory( plaintextPath, "release" );
#endif

    rLog( Info, "releasing %s", naming->encodePath( plaintextPath ).c_str() );
    
    Lock _lock( mutex );

    CacheMap::iterator it = openFiles.find( HASHKEY(plaintextPath) );

    if(it != openFiles.end())
    {
	FileNode *fnode = it->second;
	rAssert(fnode != NULL);

	// some trickly locking stuff going on here...
	Lock fnodeLock( fnode->mutex );

	if( --fnode->retainCount == 0 )
	{
	    rLog( Info, "removing FileNode %s from map", 
		    naming->encodePath( plaintextPath ).c_str());
	
	    // storedName tries to make use of shallow copy to clear memory
	    // used for storing filenames.. Not really sure if it does any
	    // good.
	    string storedName = it->first;
	    openFiles.erase( it );
	    storedName.assign( storedName.length(), '\0' );

	    if(fnode->refCnt == 0)
	    {
		// mutex held going into ~FileNode.  we never unlock it..
		fnodeLock.leave();
		delete fnode;
	    }
	}
    } else
    {
	rWarning("unexpected release call for %s",
		naming->encodePath( plaintextPath ).c_str());
#if REQUEST_HISTORY
	showHistory( plaintextPath );
#endif
    }
}

static void removeFromCache( std::vector<FileNode*> &cache,
	FileNode *node )
{
    for(int i=0; i<RecentNodeCacheSize; ++i)
    {
	if( cache[i] == node )
	{
	    cache[i] = NULL;
	    FileNodeDestructor( node );
	    break;
	}
    }
}

static void removeFromCache( std::vector<FileNode*> &cache,
	const char *plainName )
{
    for(int i=0; i<RecentNodeCacheSize; ++i)
    {
	if( cache[i] != NULL && !strcmp(cache[i]->plaintextName(), plainName ))
	{
	    FileNode *fnode = cache[i];
	    cache[i] = NULL;
	    FileNodeDestructor( fnode );
	    break;
	}
    }
}

/*
    rename just internal cache nodes.  The node is keyed by filename, so a
    rename means the internal node names must be changed.

*/
FileNode * DirNode::renameNode( const char *from, const char *to )
{
    return renameNode( from, to, true );
}

FileNode * DirNode::renameNode( const char *from, const char *to, 
	bool forwardMode )
{
    // don't want there to be two nodes with the same name!
    removeFromCache( recentNodes, to );

    bool inMap = false;
    bool created = false;
    FileNode *node = findOrCreate( from, "renameNode", &inMap, &created );

    if(node)
    {
	Lock nodeLock( node->mutex );

	uint64_t newIV = 0;
	string cname = rootDir + naming->encodePath( to, &newIV );

	rLog(Info, "renaming internal node %s -> %s",
		node->cipherName(), cname.c_str());

	if(node->setName( to, cname.c_str(), newIV, forwardMode ))
	{
	    if(inMap)
	    {
		openFiles.erase( HASHKEY(from) );
		openFiles.insert( make_pair( HASHKEY(to), node ) );
	    }
	} else
	{
	    // rename error! - put it back 
	    rError("renameNode failed");
	    // TODO: leaks a node reference count here...
	    throw ERROR("Internal node name change failed!");
	}
    }

    FileNodeDestructor( node );

    return node;
}

FileNode *DirNode::findNode( const char *plainName, bool *inMap )
{
    rAssert( inMap != NULL );

    FileNode *node = NULL;

    // first check the cache node list, to avoid unecessary thrashing..
    for(int i=0; i<RecentNodeCacheSize; ++i)
    {
	FileNode *tmpNode = recentNodes[i];
	if(tmpNode != NULL && !strcmp(tmpNode->plaintextName(), plainName))
	{
	    node = tmpNode;
#if CACHE_STATS
	    int cacheNum = (nextCacheLoc + RecentNodeCacheSize-1 - i) %
		RecentNodeCacheSize;
	    ++cacheHits[ cacheNum ];
#endif
	    *inMap = false;
	    break;
	}
    }

    if(!node)
    {
#if CACHE_STATS
	++cacheMiss;
#endif

	// check if the name is in the open-file cache..
	CacheMap::const_iterator it = openFiles.find( HASHKEY(plainName) );

	if(it != openFiles.end())
	{
	    node = it->second;
	    rAssert(node != NULL);
	    *inMap = true;
	}
    }

    return node;
}

FileNode *DirNode::findOrCreate( const char *plainName, const char *requestor,
	bool *inMap, bool *created )
{
    rAssert( inMap != NULL );
    rAssert( created != NULL );

#if REQUEST_HISTORY
    addHistory( plainName, requestor );
#else
    // don't complain about unused vars..
    (void)requestor;
#endif

    // don't use ATIME_ATOMIC_UPDATE macro because we're already in locked
    // region
    if(inactivityTimer)
	lastAccess = time(0);
    
    FileNode *node = findNode( plainName, inMap );

    if(node)
    {	
	node->incRef();
	*created = false;
    } else
    {
	uint64_t iv = 0;
	string cipherName = naming->encodePath( plainName, &iv );
	node = new FileNode( this, 
		config->fsSubVersion,
		plainName, 
		(rootDir + cipherName).c_str(), 
		config->cipher, config->key,
		config->blockSize, config->blockMACBytes,
		config->blockMACRandBytes, 
		config->uniqueIV,
		config->externalIVChaining,
		config->forceDecode);
		
	if(config->externalIVChaining)
	    node->setName(0, 0, iv);

	rLog(Info, "created FileNode for %s", node->cipherName());
	*inMap = false;
	*created = true;
    }

    return node;
}

Ptr<FileNode>
DirNode::lookupNode( const char *plainName, const char * requestor )
{
    Lock _lock( mutex );

    bool inMap = false;
    bool created = false;
    FileNode *node = findOrCreate( plainName, requestor, &inMap, &created );

    if(created && node && !inMap)
    {
	// retain a copy in in recent nodes list..
	if( recentNodes[ nextCacheLoc ] )
	    FileNodeDestructor( recentNodes[ nextCacheLoc ] );

	node->incRef();

	recentNodes[ nextCacheLoc ] = node;
	if(++nextCacheLoc >= RecentNodeCacheSize)
	    nextCacheLoc = 0;
    }

    // Return a fresh Ptr<> wrapper.  We don't share wrappers because that
    // would introduce race conditions on the wrapper.  We use it only to
    // ensure that an appropriate file node destructor is called when the
    // caller finishes with it.
    return Ptr<FileNode>(node, FileNodeDestructor);
}

/*
    Similar to lookupNode, except that we also call open() and only return a
    node on sucess..  This is done in one step to avoid any race conditions
    with the stored state of the file.
*/
Ptr<FileNode>
DirNode::openNode( const char *plainName, const char * requestor, int flags,
	int *result )
{
    rAssert( result != NULL );
    Lock _lock( mutex );

    bool inMap = false;
    bool created = false;
    FileNode *node = findOrCreate( plainName, requestor, &inMap, &created );

    if( (*result = node->open( flags )) >= 0 )
    {
	node->incRetain();
    
	if(!inMap)
	{
	    openFiles.insert( make_pair( HASHKEY(plainName), node ) );
	    if(!created)
		removeFromCache( recentNodes, node );
	}

       	return Ptr<FileNode>(node, FileNodeDestructor);
    } else
    {
	// error.. undo..
	FileNodeDestructor( node );

	return Ptr<FileNode>();
    }
}

int DirNode::unlink( const char *plaintextName )
{
    rLog( Info, "unlink %s", naming->encodePath( plaintextName ).c_str() );

    Lock _lock( mutex );
    
    int res = 0;

    CacheMap::const_iterator it = openFiles.find( HASHKEY(plaintextName) );
    if(it != openFiles.end())
    {
	// If we aren't using a version of FUSE with file-hide support, then we
	// can't allow the unlink of an open file!
	/*
	    This happens if a file is retained in the cache. 

	    The only reason for a file to be retained now is because it was
	    opened and we're keeping it around until it if fully released.
	    
	    We don't have a way to support Unix's delete while open semantics
	    because then we'd be in trouble if another open came along. 
	*/
	rWarning("Refusing to unlink cached file: %s (%i ref, %i retain)",
		it->second->cipherName(),
		it->second->refCnt, it->second->retainCount);
	res = -EBUSY;
    }

    if(res == 0)
    {
	removeFromCache( recentNodes, plaintextName );

	string cyName = rootDir + naming->encodePath( plaintextName );
	res = ::unlink( cyName.c_str() );
	if(res == -1)
	{
	    res = -errno;
	    rDebug("unlink error: %s", strerror(errno));
	} else
	    res = 0;
    }
	
    return res;
}

