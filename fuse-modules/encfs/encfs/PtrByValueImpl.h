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

#ifndef _PtrByValueImpl_incl_
#define _PtrByValueImpl_incl_


#include "PtrImpl.h"


namespace rel
{
    /*
	implementation of OpaqueValueData for by-value types. 
	This stores the data by value rather then as a pointer.
     */
    template<typename Type>
    class OVDValueImpl : public OVDRefCounted
    {
    public:
	OVDValueImpl(Type src, void (*destructor)(Type))
	    : OVDRefCounted()
	    , value(src)
	    , destroyOp(destructor) {}
	// no destructor
	OVDValueImpl(Type src)
	    : OVDRefCounted()
	    , value(src)
	    , destroyOp(0) {}

	virtual ~OVDValueImpl() {} 

	virtual void *getValue() const {return (void*)&value;}
	virtual const std::type_info &type() const {return typeid(Type);}

	virtual void destroy()
	{
	    if(destroyOp)
		(*destroyOp)(value);
	}

    private:
	Type value;
	// destructor helper
	void (*destroyOp)(Type);
    };

} // namespace rel

#endif
