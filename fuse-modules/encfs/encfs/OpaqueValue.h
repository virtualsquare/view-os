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
		                                                                                
#ifndef _OpaqueValue_incl_
#define _OpaqueValue_incl_

namespace rel
{
    class OpaqueValue;

    /**
      Base class for underlying implementation of smart pointer.  This defines
      all the operations that a smart pointer should be capable of doing:

      - get the valeu
      - get the type information about the value
      - clone itself
      - increment the retain count
      - decrement the retain count

    */
    class OpaqueValueData
    {
    public:
	virtual ~OpaqueValueData();

	/** get pointer to data */
	virtual void *getValue() const =0;

	/** get type information */
	virtual const std::type_info &type() const =0;

	/** clone existing opaque value data.  Returns 'this' by default.
	  This does not change the reference count..  retain() should be called
	  on the clone, and release() when done with it.
	*/
	virtual OpaqueValueData *clone();

	/** retain opaque value data.  Should be called by anyone wanting to
	 * keep the value around.
	*/
	virtual void retain() =0;

	/** release opaque value data.  Returns true if the data can now be
	  freed.
	 */
	virtual bool release() =0;

	/** attempt to cast to another type.  This allows the value
	 * being converted supply its own means of recasting.
	*/
	virtual bool castTo(const std::type_info &resultType,
		OpaqueValue *output);
    };

    /**
      Rel's base smart pointer class.  This can hold any type of object, along
      with a symbolic type id string which is used for error checking.

      Due to the type checking string, an OpaqueValue can only be cast to the
      same type it was stored as.  For example, if class B is derived from
      class A, and an instance of type B is stored, it can not be pulled out as
      type A.

      In order to be able to hold arbitrary type data, this also holds
      additional data about an object, such as the destruction function.

      All of this extra information is transparent to the user.  For instance,
      if we knew a type "int" was stored in a map, we could look it up as
      follows:

      @code
      Ptr<int> result = GlobalObjectMap()->find(Path("..."));
      @endcode

      The find operation always returns OpaqueData, which can be automatically
      cast to Ptr<Type> - which does type checking along the way.
      Attempting to cast to the wrong type will lead to an exception.  See
      Ptr<> for details.
     */
    class OpaqueValue
    {
    public:
	OpaqueValue();
	OpaqueValue(const OpaqueValue &value);
	OpaqueValue(OpaqueValueData *value);
	~OpaqueValue();

	/** Return the C++ type specifier for this value */
	const std::type_info &type() const;

	OpaqueValue &operator=(const OpaqueValue &src);

	/**
	    Get a pointer to the data being stored.   The OpaqueValue retains
	    ownership of the data, so this should be used with care.
	 */
	void *get() const;

	/** isEmptySet returns true if the OpaqueValue does not point to
	  anything.  Even it if points to something, it is still possible that
	  that something will eventually evaluate to be a zero...  This is like
	  an empty-set test, rather then a test for zero.  These may be
	  indistinguishable in some cases.
	 */
	bool isEmptySet() const;

	/** similar to isEmptySet, except that this also checks that the value
	  pointed to is not null.  This is useful if you are about to
	  dereference the pointer (eg   ptr->func() ), as isEmptySet() doesn't
	  guarentee you won't get a NULL dereference in that case..
	 */
	bool isNull() const;

	/** check that the current type matches the destination type.  Returns
	  false if they do not match.
	 */
	bool checkType(const std::type_info &dst);
	/** just like checkType, except that it calls rFatal if the
	  types do not match.
	 */
	void assertType(const std::type_info &dst);

	/** Reset the value.  This is used mostly to reset to NULL.  These two
	 * are the same:
	 @code
	 OpaqueValue myValue;

	 // reset to null pointer.
	 myValue.reset();

	 // this should be true now..
	 assert_rFatal(myValue.isEmptySet() == true);
	 assert_rFatal(myValue.isNull() == true);


	 // here is another way to reset to null pointer -- assign to one.
	 myValue = OpaqueValue();

	 assert_rFatal(myValue.isEmptySet() == true);
	 assert_rFatal(myValue.isNull() == true);

	 @endcode
	*/
	void reset(OpaqueValueData *value = 0);

	OpaqueValueData *getData() const;

    protected:
	/* throw a bad_operation error if value is NULL.  This is here only
	   for convenience, so that the code is not left in the header file.
	*/
	static void assertNotNull(const void *value);
	static void assertNull(const void *value);

    private:
	OpaqueValueData *data;
    };


    // shortcut - returns a NULL value.  The result has these properties:
    // isNull() returns TRUE,
    // isEmptySet() returns FALSE.
    // This can be done by hand by doing:
    // OpaqueValue(new OVDPtrImpl<void>(NULL, (void(*)(void*))NULL));
    OpaqueValue nonEmptySetNull();


	
    inline void *OpaqueValue::get() const
    { 
	return data ? data->getValue() : 0; 
    }
	
    inline OpaqueValueData *OpaqueValue::getData() const 
    {
	return data;
    }

    inline bool OpaqueValue::isEmptySet() const 
    { 
	return (data == 0); 
    }

    inline bool OpaqueValue::isNull() const 
    { 
	return (data ? (data->getValue() == 0) : true); 
    }


} // namespace rel

#endif

