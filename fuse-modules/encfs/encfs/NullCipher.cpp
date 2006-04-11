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

#include "NullCipher.h"

#include "Range.h"
#include "Interface.h"

#include <rlog/rlog.h>

using namespace std;
using namespace rel;
using namespace rlog;


static Interface NullInterface( "nullCipher", 1, 0, 0 );
static Range NullKeyRange(0);
static Range NullBlockRange(1,4096,1);

static Ptr<Cipher> NewNullCipher(const Interface &iface, int keyLen)
{
    (void)keyLen;
    return Ptr<Cipher>( new NullCipher( iface ) );
}

const bool HiddenCipher = true;

static bool NullCipher_registered = Cipher::Register("Null",
	"Non encrypting cipher.  For testing only!",
	NullInterface, NullKeyRange, NullBlockRange, NewNullCipher,
	HiddenCipher);

struct NullKey
{

} gNullKey;

NullCipher::NullCipher(const Interface &iface_)
{
    this->iface = iface_;
}

NullCipher::~NullCipher()
{
}

Interface NullCipher::interface() const
{
    return iface;
}

CipherKey NullCipher::newKey(const char *, int )
{
    // no destructor..
    return Ptr<NullKey>( &gNullKey, (void*)NULL );
}

CipherKey NullCipher::newRandomKey()
{
    // no destructor..
    return Ptr<NullKey>( &gNullKey, (void*)NULL );
}

void NullCipher::randomize( unsigned char *buf, int len ) const
{
    memset( buf, 0, len );
}

uint64_t NullCipher::MAC_64(const unsigned char *, int , 
	const CipherKey &, uint64_t *) const
{
    return 0;
}

CipherKey NullCipher::readKey( const unsigned char *, 
	const CipherKey &, bool)
{
    // no destructor..
    return Ptr<NullKey>( &gNullKey, (void*)NULL );
}

void NullCipher::writeKey(const CipherKey &, unsigned char *, 
	const CipherKey &)
{
}

bool NullCipher::compareKey(const CipherKey &A_, 
	const CipherKey &B_) const
{
    Ptr<NullKey> A = A_;
    Ptr<NullKey> B = B_;
    return A.get() == B.get();
}

int NullCipher::encodedKeySize() const
{
    return 0;
}

int NullCipher::keySize() const
{
    return 0;
}

int NullCipher::cipherBlockSize() const
{
    return 1;
}

bool NullCipher::streamEncode( unsigned char *src, int len,
	uint64_t iv64, const CipherKey &key) const
{
    (void)src;
    (void)len;
    (void)iv64;
    (void)key;
    return true;
}

bool NullCipher::streamDecode( unsigned char *src, int len,
	uint64_t iv64, const CipherKey &key) const
{
    (void)src;
    (void)len;
    (void)iv64;
    (void)key;
    return true;
}

bool NullCipher::blockEncode( unsigned char *, int , uint64_t, 
	const CipherKey & ) const
{
    return true;
}

bool NullCipher::blockDecode( unsigned char *, int, uint64_t, 
	const CipherKey & ) const
{
    return true;
}

bool NullCipher::Enabled()
{
    return true;
}

