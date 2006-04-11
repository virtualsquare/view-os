/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2003, Valient Gough
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

#ifndef _LinkedOwner_incl_
#define _LinkedOwner_incl_

//#pragma interface

namespace rel
{

    /*
	Forms a doubly-linked list of all the instances sharing some data.
	In copy constructors and assignment operations, use shareOwnership to
	share ownership with an existing owner (adds self to linked list of
	owners).  Call dropOwnership() to release oneself from responsibility
	of owned data.  If dropOwnership returns true, then you were the last
	owner and must dispose of the data properly.

	This can be useful for non-virtual classes which want fase shallow-copy
	copy constructors and assignment operations.  It is efficient because
	it doesn't need to allocate memory for a reference count.
    */
    class LinkedOwner
    {
    public:
	LinkedOwner();

	void shareOwnership(const LinkedOwner *src);

	// returns TRUE if we were the last owner and therefor must destroy the
	// value.
	bool dropOwnership();

    protected:
	LinkedOwner *_leftOwner;
	LinkedOwner *_rightOwner;
    };

    inline void LinkedOwner::shareOwnership(const LinkedOwner *src)
    {
	_leftOwner = const_cast<LinkedOwner*>(src);
	_rightOwner = src->_rightOwner;
	_leftOwner->_rightOwner = _rightOwner->_leftOwner = this;
    }

}


#endif
