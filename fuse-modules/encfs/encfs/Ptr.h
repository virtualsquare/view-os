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
		                                                                                
#ifndef _Ptr_incl_
#define _Ptr_incl_

#include "OpaqueValue.h"
#include "PtrImpl.h"
#include "PtrByValueImpl.h"


//#pragma interface

#define NULL_DESTRUCTOR (void*)0
#define NO_DESTRUCTOR (void*)0

namespace rel
{

    /**
      Default destructor for a Ptr, if none is specified.  This defaults
      to using C++'s delete operator to destroy the value on retirement.

      @relates Ptr
    */
    template<typename Type>
    void defaultDestructorFunc(Type *data)
    {
	delete data;
    }

    /**
      Destructor which which can be used in Ptr for malloc allocated
      strings.  It calls free() on the value.

      For example:

      @code

      // create a smart pointer to hold onto a malloc'd memory hunk.  It will
      // call freeDestructor() when the last instance is destroyed.
      Ptr<char> data((char*)malloc(size), &freeDestructor);

      @endcode

      @relates Ptr
    */
    void freeDestructor(char *data);

    /**
      Ptr derives from OpaqueValue and provides extra interfaces when the
      type of the object is known.

      Casts from a Ptr<Type> to an OpaqueValue (hiding type information)
      are the same complexity as a copy or assignment operation between two
      OpaqueValues.  

      Casts from an OpaqueValue to a Ptr<Type> are more expensive because
      the type must be checked to ensure compatibility.
    */
    template<typename Type>
    class Ptr : public OpaqueValue
    {
    public:
	/** Create a Null pointer of the appropriate type.  More specifically,
	  this is an EmptySet, and isEmptySet() and isNull() will both return
	  true.

	  Note that an empty set when cast to an OpaqueValue looses all type
	  information, because an OpaqueValue empty set may be cast to any
	  Ptr type without error.

	  In order to create a pointer which is NULL, but not an empty set
	  (that is, it has a value of NULL rather then no value at all), use
	  the constructor:

	  Ptr<Type>(NULL, OpaqueValue::No_Destructor);
	*/
	Ptr() {}

	~Ptr() {}

	/**  Construct a Ptr from an OpaqueValue.  This checks the type
	  before making a shallow copy.  If the type is wrong, a rel::bad_cast
	  exception is throw.
	*/
	Ptr( const OpaqueValue &untyped ) 
	    : OpaqueValue(untyped)
	    { 
		assertType(typeid(Type));
	    }

#if 0
	// For automatic cast from RELVariant
	Ptr( const RELVariant &untyped ) 
	    : OpaqueValue(untyped.toOpaque())
	    { 
		assertType(typeid(Type));
	    }
#endif

	/**
	  Copy constructor.  This makes a shallow copy of the data.
	*/
	Ptr( const Ptr<Type> &src ) 
	    : OpaqueValue(src)
	    {}

	/** Take ownership of a value.  This constructor is marked explicit,
	   because it should only be used knowingly.  Since this takes
	   ownership, when the last smart pointer reference to this value is
	   destroyed, the value itself will be destroyed using the default
	   destructor function.
	 */
	explicit Ptr(Type *value)
	    : OpaqueValue(new OVDPtrImpl<Type>(value, 
			&defaultDestructorFunc<Type>))
	    {}

	/** This constructor defines no destruction operation for the value.
	   When the last smart pointer reference is destroyed, nothing happens
	   to the value.  This is useful for holding pointers to values which
	   should never be destroyed (such as static variables).

	   The second value should always be NULL.
	*/
	Ptr(Type *value, void *noDestructor)
	    : OpaqueValue(new OVDPtrImpl<Type>(value, (void(*)(Type*))0))
	    {assertNull(noDestructor);}

	/** This constructs a smart pointer which stores the data by-value,
	   rather then by pointer.  It also defines no destruction operation.

	   This is useful for holding pointers to functions, as they require no
	   destruction, and they are already pointers, so it makes sense to
	   stoe them by-value.
	   
	   The second value should always be NULL.
	 */
	Ptr(Type value, void *noDestructor)
	    : OpaqueValue(new OVDValueImpl<Type>(value, (void(*)(Type))0))
	    {assertNull(noDestructor);}

	/** Allow specifying a user-defined destructor function.  The
	   destructor function will be called when the last smart pointer
	   reference to this data is destroyed.
	 */
	Ptr(Type *value, void (*destructorFunc)(Type *))
	    : OpaqueValue(new OVDPtrImpl<Type>(value, destructorFunc))
	    {}

	/** Allow specifying a user-defined destructor function for a by-value
	   smart pointer.  The destructor function will be called when the last
	   smart pointer reference to this data is destroyed.

	   Any type of function may be used here - it doesn't have to actually
	   do anything related to memory management.  For example, one use of
	   Ptr<int> is to store file descriptors, where the "destructor"
	   calls close() on the descriptor.
	 */
    	Ptr(Type value, void(*destructor)(Type))
	    : OpaqueValue(new OVDValueImpl<Type>(value, destructor))
	    {}

	
	Ptr &operator =( const OpaqueValue &untyped ) 
	{ 
	    // We can't do the assertType until we've copied the data, since
	    // assertType needs the data.
	    OpaqueValue::operator=(untyped);
	    assertType(typeid(Type));
	    return *this;
	}

#if 0
	// for automatic cast from RELVariant
	Ptr &operator =( const RELVariant &untyped )
	{
	    return (*this = untyped.toOpaque() );
	}
#endif

	// perform a cast (like operator=), but don't print any error messages
	// if it failes.  Returns true if the cast was successful and the
	// result is not null.
	bool silentCast(const OpaqueValue &untyped)
	{
	    OpaqueValue::operator=(untyped);
	    if(!checkType(typeid(Type)))
	    {
		reset();
		return false;
	    } else
		return !isNull();
	}

	Type *get() const          
	{ 
	    return (Type*)OpaqueValue::get();
	}

#ifdef AUTOMATIC_PTR_CAST
	Type &operator *() const   
	{ 
	    Type *value = get();
	    assertNotNull((void*)value);
	    return *value;
	}
	operator Type*() const     { return   get(); }
#endif

	Type *operator ->() const  
	{ 
	    Type *value = get();
	    assertNotNull((void*)value);
	    return value;
	}

	void reset(Type *value = (Type *)0)
	{
	    if(!value)
		OpaqueValue::reset();
	    else
	    {
		OpaqueValue::reset(new OVDPtrImpl<Type>(value,
			    &defaultDestructorFunc<Type>));
	    }
	}

	void reset(Type value, void(*destructor)(Type))
	{
	    OpaqueValue::reset(new OVDValueImpl<Type>(value,destructor));
	}
    };

} // namespace rel

#endif

