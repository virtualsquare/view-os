/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2001, Valient Gough
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
              
#include "OpaqueValue.h"
#include "PtrImpl.h"
#include <rlog/rlog.h>

#include <stdlib.h>

using namespace std;
using namespace rel;


OpaqueValue rel::nonEmptySetNull()
{
    static OpaqueValue result(new OVDPtrImpl<void>(0, (void(*)(void*))NULL));
    return result;
}



OpaqueValue::OpaqueValue()
    : data(NULL)
{
}

OpaqueValue::OpaqueValue(const OpaqueValue &value)
{
    data = value.data ? value.data->clone() : NULL;
    if(data)
	data->retain();
}

OpaqueValue::OpaqueValue(OpaqueValueData *value)
    : data(value)
{
    if(data)
	data->retain();
}

OpaqueValue::~OpaqueValue()
{
    if(data && data->release())
	delete data;
    data = NULL;
}

const type_info &OpaqueValue::type() const
{
    return data ? data->type() : typeid(void);
}

OpaqueValue &OpaqueValue::operator=(const OpaqueValue &src)
{
    reset(src.data ? src.data->clone() : NULL);
    return *this;
}

void OpaqueValue::assertType(const std::type_info &dst)
{
    if(!checkType(dst))
    {
	if(type() != typeid(void))
	    rDebug("type %s doesn't match %s", type().name(), dst.name());
	reset();
	_rAssertFailed( RLOG_COMPONENT, "Type mismatch" );
    }
}

void OpaqueValue::assertNotNull(const void *value)
{
    rAssert(value);  // "Attempted to dereference NULL pointer"
}

void OpaqueValue::assertNull(const void *value)
{
    rAssert(!value); // "Expecting NULL"
}

bool OpaqueValue::checkType(const std::type_info &dst)
{
    bool ok = true;
    while(data && data->type() != dst)
    {
	// type mismatch.  See if we can cast to the desired type..
	OpaqueValue result;
	if(data->castTo(dst, &result))
	{
	    // we only run the cast once, then we keep the new value, not
	    // the old.  That way we avoid possible side effect problems if the
	    // cast function is called multiple times due to different
	    // cast attempts..
	    *this = result;
	} else
	{
	    ok = false;
	    break;
	}
    }
    return ok;
}

void OpaqueValue::reset(OpaqueValueData *value)
{
    if(value)
	value->retain();

    if(data && data->release())
	delete data;

    data = value;
}



OpaqueValueData::~OpaqueValueData()
{
}

OpaqueValueData *OpaqueValueData::clone()
{
    return this;
}

bool OpaqueValueData::castTo(const std::type_info &,
	OpaqueValue *)
{
    // TODO: should we try and do a dynamic cast here using VMap?  That is an
    // expensive test, but on the other hand this shouldn't happen so often,
    // right?

    return false;
}

