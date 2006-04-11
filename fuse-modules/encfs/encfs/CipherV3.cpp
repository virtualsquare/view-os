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
 *
 */

#include "CipherV3.h"
#include "Interface.h"
#include "Mutex.h"

#include "../config.h"

#include <string.h>

#define NO_DES

#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <rlog/rlog.h>

#include "i18n.h"

using namespace std;
using namespace rel;
using namespace rlog;


/*
    - Version 1:0, is as used by EncFS 0.2 - 0.6.  Here mostly for backward
      compatibility, and for systems with old OpenSSL versions which don't have
      new enough interfaces to support the new SSL_Cipher code..

    - Version 2:0, adds support for IV chaining.
*/
static Interface CipherV3Iface( "ssl/blowfish-v0.2", 2, 0, 1 );
static Range V3KeyRange(160,160,1);  // fixed length - 160 bits
static Range V3BlockRange(64,64,1);  // fixed length - 64 bytes

static Ptr<Cipher> NewBF(const Interface &iface, int keyLen)
{
    (void)keyLen;
    return Ptr<Cipher>( new CipherV3(iface) );
}

static bool BF_registered = Cipher::Register("blowfish-compat", 
	// description of algorithm for backward compatibility with old encfs
	// filesystems..
	// xgroup(setup)
	gettext_noop("algorithm compatible with EncFS 0.2-0.6"), 
	CipherV3Iface, V3KeyRange, V3BlockRange, NewBF);

const int BLOCKSIZE = 64;

// TODO: less then about 6 rounds aren't enough for avalanche in all cases.
// How badly do we want to couple all bytes in each block?
// 2 rounds gives about 8 bytes of avalanche for a blocksize of 32 
// - similar to using BF_cbc_encrypt
// XXX: 2 rounds is the minimum, because we swap the array direction each
// round, and we want the last bytes to depend at least somewhat on the
// preceeding bytes.
const int CYPHER_ROUNDS = 2;

const int KEYLENGTH = SHA_DIGEST_LENGTH;
struct BlowfishKey
{
    BF_KEY key;
    unsigned char keyGenerator[KEYLENGTH];

    // access to mac_ctx must be synchronized.
    pthread_mutex_t mutex;
    HMAC_CTX mac_ctx;

    void initKey();

    BlowfishKey();
    ~BlowfishKey();
};

BlowfishKey::BlowfishKey()
{
    pthread_mutex_init( &mutex, NULL );
    memset(keyGenerator, 0, KEYLENGTH);
#ifdef HAVE_HMAC_INIT_EX
    HMAC_CTX_init( &mac_ctx );
#endif
}

BlowfishKey::~BlowfishKey()
{
#ifdef HAVE_HMAC_INIT_EX
    HMAC_CTX_cleanup( &mac_ctx );
#endif
    pthread_mutex_destroy( &mutex );
}

void BlowfishKey::initKey()
{
    Lock _lock( mutex );
    BF_set_key( &key, KEYLENGTH, keyGenerator );
#ifdef HAVE_HMAC_INIT_EX
    HMAC_Init_ex( &mac_ctx, keyGenerator, KEYLENGTH, EVP_sha1(), 0 );
#else
    HMAC_Init( &mac_ctx, keyGenerator, KEYLENGTH, EVP_sha1() );
#endif
}

static uint64_t _checksum_64( const unsigned char *data, int dataLen,
	const CipherKey &_key, uint64_t *chainedIV )
{
    Ptr<BlowfishKey> key( _key );

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = EVP_MAX_MD_SIZE;

    unsigned char *mdigest = &md[0];

    Lock _lock( key->mutex );

#ifdef HAVE_HMAC_INIT_EX
    HMAC_Init_ex( &key->mac_ctx, 0, 0, 0, 0 );
#else
    HMAC_Init( &key->mac_ctx, 0, 0, 0 );
#endif
    HMAC_Update( &key->mac_ctx, data, dataLen );

    if(chainedIV)
    {
	uint64_t tmp = *chainedIV;
	unsigned char h[8];
	for(unsigned int i=0; i<8; ++i)
	{
	    h[i] = tmp & 0xff;
	    tmp >>= 8;
	}
	HMAC_Update( &key->mac_ctx, h, 8 );
    }
    HMAC_Final( &key->mac_ctx, md, &mdLen );

    rAssert(mdigest != 0);

    // chop down to a 64bit value
    unsigned char h[8] = {0};
    for(unsigned int i=0; i<(mdLen-1); ++i)
	h[i%8] ^= (unsigned char)(md[i]);

    uint64_t value = (uint64_t)h[0];
    for(int i=1; i<8; ++i)
	value = (value << 8) | (uint64_t)h[i];

    return value;
}

static unsigned int _checksum_16( const unsigned char *data, int dataLen,
	const CipherKey &_key )
{
    Ptr<BlowfishKey> key( _key );

    static const EVP_MD *evp_md = EVP_sha1();

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = EVP_MAX_MD_SIZE;

    unsigned char *mdigest = 
	HMAC( evp_md, key->keyGenerator, KEYLENGTH, data, 
		dataLen, md, &mdLen);

    rAssert(mdigest != 0);
    // chop this down to a 16bit value..
    unsigned char h1 = 0;
    unsigned char h2 = 0;
    for(unsigned int i=0; i<(mdLen-1); i+=2)
    {
	h1 ^= (unsigned char)(mdigest[i]);
	h2 ^= (unsigned char)(mdigest[i+1]);
    }

    return ((((unsigned int)h1) << 8) | ((unsigned int)h2));
}


CipherV3::CipherV3( const rel::Interface &iface_ )
{
    this->iface = iface_;
}

CipherV3::~CipherV3()
{
}

Interface CipherV3::interface() const
{
    return CipherV3Iface;
}

/*
    create a blowfish key from the password.
    Use SHA to distribute entropy from the password into the key.

    This algorithm must remain constant for backward compatibility.
*/
CipherKey CipherV3::newKey(const char *password, int passwdLength)
{
    Ptr<BlowfishKey> key (new BlowfishKey);
    SHA1( (const unsigned char*)password, passwdLength, key->keyGenerator );

    key->initKey();

    return key;
}

void CipherV3::randomize( unsigned char *buf, int len ) const
{
    memset( buf, 0, len );
    if(RAND_bytes( buf, len ) == 0)
    {
	char errStr[120];
	unsigned long errVal = 0;
	if((errVal = ERR_get_error()) != 0)
	{
	    rWarning("openssl error: %s", ERR_error_string( errVal, errStr ));
	}
    }
}

/*
    Create a random key.
    We use the OpenSSL library to generate random bytes, then take the hash of
    those bytes to use as the key.

    This algorithm can change at any time without affecting backward
    compatibility.
*/
CipherKey CipherV3::newRandomKey()
{
    Ptr<BlowfishKey> key (new BlowfishKey);
    unsigned char tmpBuf[ KEYLENGTH ];
    memset( tmpBuf, 0, KEYLENGTH );
    if(RAND_bytes( tmpBuf, KEYLENGTH ) == 0)
    {
	char errStr[120];
	unsigned long errVal = 0;
	if((errVal = ERR_get_error()) != 0)
	{
	    rWarning("openssl error: %s", ERR_error_string( errVal, errStr ));
	    return CipherKey();
	}
    }

    // take the hash, in case the RAND_bytes data isn't uniformly random..
    SHA1( tmpBuf, KEYLENGTH, key->keyGenerator );

    key->initKey();

    return key;
}

bool
CipherV3::compareKey( const CipherKey &A, const CipherKey &B ) const
{
    Ptr<BlowfishKey> key1 = A;
    Ptr<BlowfishKey> key2 = B;

    if(memcmp( key1->keyGenerator, key2->keyGenerator, KEYLENGTH ) == 0)
	return true;
    else
	return false;
}

CipherKey CipherV3::readKey(const unsigned char *data, 
	const CipherKey &masterKey, bool checkKey)
{
    unsigned int checksum = ((unsigned int)(data[KEYLENGTH])) << 8
	                  | ((unsigned int)(data[KEYLENGTH+1]));

    unsigned char tmpBuf[ KEYLENGTH ];
    memcpy( tmpBuf, data, KEYLENGTH );
    nameDecode( tmpBuf, KEYLENGTH, checksum, masterKey );

    if(checkKey)
    {
	unsigned int checksum2 = _checksum_16( tmpBuf, KEYLENGTH, masterKey );
	if(checksum != checksum2)
	{
	    rDebug("checksum mismatch: expected %u, got %u", checksum,
		    checksum2);
	    return CipherKey();
	}
    }

    Ptr<BlowfishKey> key ( new BlowfishKey );
    memcpy( key->keyGenerator, tmpBuf, KEYLENGTH );

    key->initKey();

    return key;
}

void CipherV3::writeKey(const CipherKey &key_, unsigned char *data, 
	const CipherKey &masterKey)
{
    Ptr<BlowfishKey> key = key_;
    memcpy( data, key->keyGenerator, KEYLENGTH );
    unsigned int checksum = _checksum_16( data, KEYLENGTH, masterKey );

    nameEncode( data, KEYLENGTH, checksum, masterKey );

    data[KEYLENGTH] = (checksum >> 8) & 0xff;
    data[KEYLENGTH+1] = (checksum) & 0xff;
}

int CipherV3::encodedKeySize() const
{
    // 2 checksum bytes
    return KEYLENGTH + 2 ;
}

int CipherV3::keySize() const
{
    return KEYLENGTH;
}

int CipherV3::cipherBlockSize() const
{
    return 8; // blowfish is an 8 byte block cipher..
}

static void setIVec( unsigned char ivec[8], unsigned int seed)
{
    unsigned int var1 = 0x060a4011 * seed;
    unsigned int var2 = 0x0221040d * (seed ^ 0xD3FEA11C);
	
    ivec[0] = (var1 >> 24) & 0xff;
    ivec[1] = (var2 >> 16) & 0xff;
    ivec[2] = (var1 >> 8 ) & 0xff;
    ivec[3] = (var2      ) & 0xff;
    ivec[4] = (var2 >> 24) & 0xff;
    ivec[5] = (var1 >> 16) & 0xff;
    ivec[6] = (var2 >> 8 ) & 0xff;
    ivec[7] = (var1      ) & 0xff;
}

static void reverse(const unsigned char *src, int size, unsigned char *dst)
{
    while(size)
	*dst++ = src[ --size ];
}

uint64_t CipherV3::MAC_64( const unsigned char *data, int dataLen,
	const CipherKey &_key, uint64_t *chainedIV ) const
{
    if( iface.current() == 1)
	return (uint64_t)_checksum_16( data, dataLen, _key ); // 0.x support
    else
    {
	// support IV chaining..
	uint64_t result = _checksum_64( data, dataLen, _key, chainedIV );
	if( chainedIV )
	    *chainedIV = result;
	return result;
    }
}


bool CipherV3::nameEncode( unsigned char *data, int len, 
	uint64_t iv64, const CipherKey &key_) const
{
    Ptr<BlowfishKey> key = key_;

    int ivecNum = 0;
    unsigned char ivec[8];

    setIVec( ivec, (unsigned int)iv64 );

    BF_cfb64_encrypt(data, data, len, &key->key, ivec, &ivecNum, BF_ENCRYPT);
    return true;
}

bool CipherV3::nameDecode( unsigned char *data, int len, 
	uint64_t iv64, const CipherKey &key_) const
{
    Ptr<BlowfishKey> key = key_;

    unsigned char ivec[8];
    int ivecNum = 0;

    setIVec( ivec, (unsigned int)iv64 );

    BF_cfb64_encrypt(data, data, len, &key->key, ivec, &ivecNum, BF_DECRYPT);
    return true;
}

/* Some possible encoding options for a block of data:
   - encode in block-cypher mode.
     Advantages:
        - change in one byte affects many other bytes, making it difficult to
	  change cyphertext without being noticed.
	- does not lead to XOR analysis attacks
     Disadvantages:
        - must always work in blocks of bytes.  Files must be padded to the
	  block size, and then the exact size stored elsewhere.
   - encode in pseudo one-time-pad mode (counter mode).
     Advantages:
        - easy to randomly seek to position in cyphertext, as each byte is
	  encoded separately.
     Disadvantages:
        - can lead to XOR based attacks if cyphertext is sent more then once
	  and has been modified.  
	- data can be changed without knowing the encryption key
   - encode in pseudo-block mode using stream cypher
     Advantages:
        - same advantages as block-cypher mode
	- blocks can be arbitrarily sized, so file does not need to be padded.
*/
static bool codePartialBlock(unsigned char *buf, int size, uint64_t iv64, 
	const CipherKey &key_, int enc)
{
    Ptr<BlowfishKey> key = key_;

    unsigned char _encBuf[ BLOCKSIZE ];
    unsigned char *encBuf = (size <= BLOCKSIZE) ? 
	_encBuf : new unsigned char [ size ];

    unsigned char ivec[8];
    for(int round = CYPHER_ROUNDS; round; --round)
    {
	int ivecNum = 0;
	setIVec( ivec, iv64 );

	// buf --> encBuf
	BF_cfb64_encrypt( (unsigned char *)buf, encBuf, size, 
		&key->key, ivec, &ivecNum, enc);

	if( round > 1 )
	{
	    // reverse, so that we can do a second pass the other direction
	    // through the bytes.  That way we make the front of the block
	    // dependent on the other end of the block.
	    //   buf <-- encBuf 
	    reverse( encBuf, size, (unsigned char *)buf );
	}
    }

    memcpy( buf, encBuf, size ); // buf <-- encBuf
    if(encBuf != _encBuf)
	delete[] encBuf;

    return true;
}

bool CipherV3::streamEncode( unsigned char *data, int len,
	uint64_t iv64, const CipherKey &key ) const
{
    return codePartialBlock(data, len, iv64, key, BF_ENCRYPT);
}

bool CipherV3::streamDecode( unsigned char *data, int len,
	uint64_t iv64, const CipherKey &key ) const
{
    return codePartialBlock(data, len, iv64, key, BF_DECRYPT);
}

bool CipherV3::blockEncode(unsigned char *buf, int size, uint64_t iv64,
	const CipherKey &key_) const
{
    Ptr<BlowfishKey> key = key_;

    unsigned char ivec[8];
    setIVec( ivec, iv64 );

    BF_cbc_encrypt( (unsigned char *)buf, (unsigned char *)buf, size, 
	    &key->key, ivec, BF_ENCRYPT);

    return true;
}

bool CipherV3::blockDecode(unsigned char *buf, int size, uint64_t iv64,
	const CipherKey &key_) const
{
    Ptr<BlowfishKey> key = key_;

    unsigned char ivec[8];
    setIVec( ivec, iv64 );

    BF_cbc_encrypt( (unsigned char *)buf, (unsigned char *)buf, size, 
	    &key->key, ivec, BF_DECRYPT);

    return true;
}

bool CipherV3::Enabled()
{
    return true;
}
