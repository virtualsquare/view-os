/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
 *
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id$
 *
 */
#include <stdio.h>
#include <config.h>
#include "module.h"
#include "gdebug.h"

struct service s;

static void
__attribute__ ((constructor))
init (void)
{
	GMESSAGE("testmodul2 init");
	s.name="TEST2";
	s.description="Test Module 2";
	s.code=0xfd;
	s.syscall=NULL;
	s.socket=NULL;
	add_service(&s);
}

static void
__attribute__ ((destructor))
fini (void)
{
	GMESSAGE("testmodul2 fini");
}       

