/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2004, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 */

#include "MACFileIOCompat.h"

#include "MemoryPool.h"

#include <rlog/rlog.h>
#include <rlog/Error.h>

#include "i18n.h"

using namespace rlog;
using namespace rel;
using namespace std;

static rel::Interface MACFileIOCompat_iface("FileIO/MAC", 1, 0, 0);

MACFileIOCompat::MACFileIOCompat( const Ptr<FileIO> &_base,
	const Ptr<Cipher> &_cipher,
	const CipherKey &_key, int fsBlockSize,
	int _macBytes, int _randBytes,
	bool warnOnlyMode )
   : BlockFileIO( fsBlockSize )
   , base( _base )
   , cipher( _cipher )
   , key( _key )
   , macBytes( _macBytes )
   , randBytes( _randBytes )
   , warnOnly( warnOnlyMode )
{
    rAssert( macBytes > 0 && macBytes <= 8 );
    rAssert( randBytes >= 0 );
}

MACFileIOCompat::~MACFileIOCompat()
{
}

rel::Interface MACFileIOCompat::interface() const
{
    return MACFileIOCompat_iface;
}

int MACFileIOCompat::open( int flags )
{
    return base->open( flags );
}

void MACFileIOCompat::setFileName( const char *fileName )
{
    base->setFileName( fileName );
}

const char *MACFileIOCompat::getFileName() const
{
    return base->getFileName();
}

bool MACFileIOCompat::setIV( uint64_t iv )
{
    return base->setIV( iv );
}

static off_t locWithHeader( off_t offset, int blockSize, int headerSize )
{
    off_t blockNum = offset / blockSize;
    int partialBlock = offset % blockSize;

    off_t adjLoc = blockNum * (blockSize + headerSize);
    if(partialBlock)
	adjLoc += (partialBlock + headerSize);

    return adjLoc;
}

static off_t locWithoutHeader( off_t offset, int blockSize, int headerSize )
{
    off_t blockNum = offset / (blockSize + headerSize);
    int partialBlock = offset % (blockSize + headerSize);

    off_t adjLoc = blockNum * blockSize;
    if(partialBlock)
    {
	rAssert( partialBlock >= headerSize );
	adjLoc += (partialBlock - headerSize);
    }

    return adjLoc;
}

int MACFileIOCompat::getAttr( struct stat *stbuf ) const
{
    int res = base->getAttr( stbuf );

    if(res == 0 && S_ISREG(stbuf->st_mode))
    {
	// have to adjust size field..
	int bs = blockSize();
	int headerSize = macBytes + randBytes;
	stbuf->st_size = locWithoutHeader( stbuf->st_size, bs, headerSize );
    }

    return res;
}

off_t MACFileIOCompat::getSize() const
{
    // adjust the size to hide the header overhead we tack on..
    int bs = blockSize();
    int headerSize = macBytes + randBytes;

    off_t size = base->getSize();
    if(size > 0)
	size = locWithoutHeader( size, bs, headerSize );

    return size;
}

ssize_t MACFileIOCompat::readOneBlock( const IORequest &req ) const
{
    int headerSize = macBytes + randBytes;

    int bs = blockSize();
    off_t blockNum = req.offset / bs;

    MemBlock mb = MemoryPool::allocate( bs + headerSize );

    IORequest tmp;
    tmp.offset = locWithHeader( req.offset, bs, headerSize );
    tmp.data = mb.data;
    tmp.dataLen = req.dataLen + headerSize;

    // get the data from the base FileIO layer
    ssize_t readSize = base->read( tmp );

    if(readSize > headerSize)
    {
	// At this point the data has been decoded.  So, compute the MAC of the
	// block and check against the checksum stored in the header..
	uint64_t mac = cipher->MAC_64( tmp.data + macBytes, 
		                       readSize - macBytes, key );

	for(int i=0; i<macBytes; ++i, mac >>= 8)
	{
	    int test = mac & 0xff;
	    int stored = tmp.data[i];
	    if(test != stored)
	    {
		// uh oh.. 
		if( !warnOnly )
		{
		    throw ERROR(
			    _("MAC comparison failure, refusing to read"));
		} else
		{
		    rWarning(_("MAC comparison failure in block %li"), 
			    (long)blockNum);
		}
	    }
	}

	// now copy the data to the output buffer
	readSize -= headerSize;
	memcpy( req.data, tmp.data + headerSize, readSize );
    } else
    {
	rDebug("readSize %i at offset %" PRIi64, (int)readSize, req.offset);
	if(readSize > 0)
	    readSize = 0;
    }

    MemoryPool::release( mb );

    return readSize;
}

bool MACFileIOCompat::writeOneBlock( const IORequest &req )
{
    int headerSize = macBytes + randBytes;

    int bs = blockSize();

    // we have the unencrypted data, so we need to attach a header to it.
    MemBlock mb = MemoryPool::allocate( bs + headerSize );

    IORequest newReq;
    newReq.offset = locWithHeader( req.offset, bs, headerSize );
    newReq.data = mb.data;
    newReq.dataLen = req.dataLen + headerSize;

    memset( newReq.data, 0, headerSize );
    memcpy( newReq.data + headerSize, req.data, req.dataLen );
    if(randBytes)
	cipher->randomize( newReq.data+macBytes, randBytes );

    // compute the mac (which includes the random data) and fill it in
    uint64_t mac = cipher->MAC_64( newReq.data+macBytes, 
	                           req.dataLen + randBytes, key );

    for(int i=0; i<macBytes; ++i)
    {
	newReq.data[i] = mac & 0xff;
	mac >>= 8;
    }

    // now, we can let the next level have it..
    bool ok = base->write( newReq );

    MemoryPool::release( mb );

    return ok;
}

int MACFileIOCompat::truncate( off_t size )
{
    int bs = blockSize();
    int headerSize = macBytes + randBytes;

    int res =  BlockFileIO::truncate( size, 0 );

    if(res == 0)
	base->truncate( locWithHeader( size, bs, headerSize ) );

    return res;
}

bool MACFileIOCompat::isWritable() const
{
    return base->isWritable();
}
