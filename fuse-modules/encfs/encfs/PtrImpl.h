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

#ifndef _PtrImpl_incl_
#define _PtrImpl_incl_

// smart pointer implementation details - things that are not normally
// necessary to view when looking at how to use a Ptr

#include <typeinfo>

#include "OpaqueValue.h"

namespace rel
{

    /*
	This derives from OpaqueValueData and provides a reference counting
	implementation, but nothing else.  In order to make a working smart
	pointer, the following must be defined in a derived class:

	 - getValue()
	 - type()
	 - destroy()

	The destroy() requirement comes from this class, which handles
	reference counting and then calls destroy() when the reference count
	reaches 0, indicating that the value contained is no longer in use.
    */
    class OVDRefCounted : public OpaqueValueData
    {
    public:
	OVDRefCounted();
	virtual ~OVDRefCounted();

	virtual void retain();
	virtual bool release();

	// must be implemented by derived class - destroy value.
	virtual void destroy() =0;

    protected:
	int refCnt;
    };
    
    /*
	Default implementation of OpaqueValueData, for storing a pointer to
	data.
     */
    template<typename Type>
    class OVDPtrImpl : public OVDRefCounted
    {
    public:
	OVDPtrImpl(Type *src, void (*destructor)(Type*))
	    : OVDRefCounted()
	    , value(src)
	    , destructor_func(destructor) {}

	virtual ~OVDPtrImpl() {value=0;}

	virtual void *getValue() const {return (void*)value;}
	virtual const std::type_info &type() const {return typeid(Type);}

	void destroy()
	{
	    if(destructor_func)
		(*destructor_func)(value);
	}

    private:
	Type *value;
	void (*destructor_func)(Type*);
    };

} // namespace rel

#endif
