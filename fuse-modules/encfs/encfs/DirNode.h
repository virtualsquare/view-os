/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2003, Valient Gough
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

#ifndef _DirNode_incl_
#define _DirNode_incl_

#include <inttypes.h>
#include <dirent.h>
#include <sys/types.h>

#include <map>
#include <list>
#include <vector>
#include <string>

#include "FileNode.h"
#include "LinkedOwner.h"
#include "NameIO.h"

#ifdef USE_HASHMAP
#include <ext/hash_map>
#endif

using rel::OpaqueValue;

class Cipher;
typedef OpaqueValue CipherKey;

class DirTraverse : public rel::LinkedOwner
{
public:
    DirTraverse(DIR *dirPtr, uint64_t iv, const NameIO *naming);
    DirTraverse(const DirTraverse &src);
    ~DirTraverse();

    DirTraverse &operator = (const DirTraverse &src);

    // returns FALSE to indicate an invalid DirTraverse (such as when
    // an invalid directory is requested for traversal)
    bool valid() const;

    // return next plaintext filename
    // If fileType is not 0, then it is used to return the filetype (or 0 if
    // unknown)
    std::string nextPlaintextName(int *fileType=0, ino_t *inode=0);

    /* Return cipher name of next undecodable filename..
       The opposite of nextPlaintextName(), as that skips undecodable names..
    */
    std::string nextInvalid();
private:
    DIR *dir; // struct DIR
    // initialization vector to use.  Not very general purpose, but makes it
    // more efficient to support filename IV chaining..
    uint64_t iv; 
    const NameIO *naming;
};
inline bool DirTraverse::valid() const { return dir != 0; }

#ifdef USE_HASHMAP
namespace __gnu_cxx
{
    template<> struct hash<std::string>
    {
	size_t operator() (const std::string &__s) const
	{
	    return __stl_hash_string( __s.c_str() );
	}
    };
}
#endif

class DirNode
{
public:
    struct Config
    {
	Ptr<Cipher> cipher; // cipher to use
	CipherKey key; // cipher key to use
	Ptr<NameIO> nameCoding; // filename encoding implementation
	int fsSubVersion; // filesystem version number at creation
	int blockSize; // file data block size
	bool inactivityTimer; // enables inactivity tracking
	int blockMACBytes; // >0 enables per-file-block MAC headers
	int blockMACRandBytes; // random bytes in MAC headers
	bool uniqueIV; // enable per-file initialization vectors
	bool externalIVChaining;
	bool forceDecode; // force decoding, even if errors are detected

	Config()
	    : fsSubVersion(0)
	    , blockSize(1)
	    , inactivityTimer( false )
	    , blockMACBytes( 0 )
	    , blockMACRandBytes( 0 )
	    , uniqueIV( false )
	    , externalIVChaining( false )
	    , forceDecode( false )
	    { }
    };

    // sourceDir points to where raw files are stored
    DirNode( const std::string &sourceDir,  const Ptr<Config> &config );
    ~DirNode();

    // return the path to the root directory
    std::string rootDirectory();

    // find files
    Ptr<FileNode> lookupNode( const char *plaintextName, 
	                      const char *requestor );

    /*
	Combined lookupNode + node->open() call.  If the open fails, then the
	node is not retained.  If the open succeeds, then the node is returned
	and the node is retained in the cache..
    */
    Ptr<FileNode> openNode( const char *plaintextName, const char *requestor,
	    int flags, int *openResult );

    std::string cipherPath( const char *plaintextPath );
    std::string plainPath( const char *cipherPath );

    // relative cipherPath is the same as cipherPath except that it doesn't
    // prepent the mount point.  That it, it doesn't return a fully qualified
    // name, just a relative path within the encrypted filesystem.
    std::string relativeCipherPath( const char *plaintextPath );

    /*
	Returns true if file names are dependent on the parent directory name.
	If a directory name is changed, then all the filenames must also be
	changed.
    */
    bool hasDirectoryNameDependency() const;

    // release file
    void release( const char *plaintextName );

    // unlink the specified file
    int unlink( const char *plaintextName );

    // traverse directory
    DirTraverse openDir( const char *plainDirName );

    // uid and gid are used as the directory owner, only if not zero
    int mkdir( const char *plaintextPath, mode_t mode,
	    uid_t uid = 0, gid_t gid = 0);

    int rename( const char *fromPlaintext, const char *toPlaintext );

    int link( const char *from, const char *to );
    
    // returns true if there are unreleased files
    bool hasOpenFiles();
  
    // returns \n separated list of open filenames.. for debugging..
    std::string openFileList();

    // returns idle time of filesystem in seconds
    int idleSeconds();


protected:

    /*
	notify that a file is being renamed. 
	This renames the internal node, if any.  If the file is not open, then
	this call has no effect.
	Returns the FileNode if it was found in the cache map.
    */
    FileNode * renameNode( const char *from, const char *to );

    /*
	when directory IV chaining is enabled, a directory can't be renamed
	without renaming all its contents as well.  recursiveRename should be
	called after renaming the directory, passing in the plaintext from and
	to paths.
    */
    bool recursiveRename( const char *from, const char *to );

private:

    struct RenameEl
    {
	// ciphertext names
	std::string oldCName;
	std::string newCName; // intermediate name (not the final cname)

	// plaintext names
	std::string oldPName;
	std::string newPName;

	bool isDirectory;
    };
    
    FileNode * renameNode( const char *from, const char *to, bool forwardMode );

    bool genRenameList( std::list<RenameEl> &list, const char *fromP,
	    const char *toP );
    void undoRename( std::list<RenameEl> &, 
	    std::list<RenameEl>::const_iterator &undoEnd);
    FileNode *findNode( const char *plainName, bool *inMap );
    FileNode *findOrCreate( const char *plainName, const char *requestor,
	    bool *inMap, bool *created );

    static void cleanList( std::list<RenameEl> &list );

    // This is a cache for a few recent unopened nodes.
    std::vector<FileNode*> recentNodes;
    int nextCacheLoc;

    pthread_mutex_t mutex;

    // passed in as configuration
    std::string rootDir;
    Ptr<Config> config;

    // Cache for open nodes, which stay arround indefinately until a release is
    // called.
#ifdef USE_HASHMAP
    typedef __gnu_cxx::hash_map<std::string, FileNode*> CacheMap;
#else
    typedef std::map<std::string, FileNode*> CacheMap;
#endif
    CacheMap openFiles;
    time_t lastAccess;

    // stored here to reduce access through config var..
    NameIO *naming;
    bool inactivityTimer;
};

#endif

