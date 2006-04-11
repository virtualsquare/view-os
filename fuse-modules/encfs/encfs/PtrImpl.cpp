/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2001-2003, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL), as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LGPL in the file COPYING for more
 * details.
 *
 */

#include "PtrImpl.h"

#include "config.h"

#include <rlog/rlog.h>

#if defined(HAVE_ATOMIC_GCC) || defined(HAVE_ATOMIC_GCC_PRIVATE)
#include <bits/atomicity.h>
#define HAVE_ATOMIC_FUNCS
#endif

#if defined(HAVE_ATOMIC_GCC_PRIVATE)
using namespace __gnu_cxx;
#endif

using namespace rel;
using namespace std;



OVDRefCounted::OVDRefCounted()
    : refCnt(0)
{

}

OVDRefCounted::~OVDRefCounted()
{
    // should never happen, or else memory is probably stuffed
    rAssert(refCnt == 0);
}

void OVDRefCounted::retain()
{
#ifdef HAVE_ATOMIC_FUNCS
    __atomic_add( &refCnt, 1 );
#else
    ++refCnt;
#endif
}

bool OVDRefCounted::release()
{
#ifdef HAVE_ATOMIC_FUNCS
    // __exchange_and_add returns what the value was *before* decrementing
    if( __exchange_and_add( &refCnt, -1) <= 1)
#else
    if(--refCnt == 0)
#endif
    {
	destroy();
	return true;
    } else
	return false;
}


