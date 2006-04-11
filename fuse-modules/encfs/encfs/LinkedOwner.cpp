/*****************************************************************************
 * Author:   Valient Gough <vgough@pobox.com>
 *
 *****************************************************************************
 * Copyright (c) 2002-2003, Valient Gough
 *
 * This library is free software; you can distribute it and/or modify it under
 * the terms of the GNU General Public License (GPL), as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GPL in the file COPYING for more
 * details.
 *
 */

#include "LinkedOwner.h"

//#pragma implementation

using namespace rel;


LinkedOwner::LinkedOwner()
    : _leftOwner( this )
    , _rightOwner( this )
{
}

bool LinkedOwner::dropOwnership()
{
    _leftOwner->_rightOwner = _rightOwner;
    _rightOwner->_leftOwner = _leftOwner;

    return ( _leftOwner == this && _rightOwner == this );
}


