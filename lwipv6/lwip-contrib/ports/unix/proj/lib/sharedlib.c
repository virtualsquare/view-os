/*   This is part of LWIPv6
 *   
 *   Copyright 2006 Diego Billi - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */ 

/*
 * This files contains the constructor and destructor functions
 * needed by the shared library.
 */

#define LIB_INIT    __attribute__ ((constructor))
#define LIB_FINI    __attribute__ ((destructor))

extern void lwip_initstack(void);
extern void lwip_stopstack(void);

void LIB_INIT
_init(void)
{
	lwip_initstack();
}

void LIB_FINI 
_fini(void)
{
	lwip_stopstack();
}
