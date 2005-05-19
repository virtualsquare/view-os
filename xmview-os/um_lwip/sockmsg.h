/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
 *
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */
#ifndef __SOCKMSG_H
#define __SOCKMSG_H

struct iovec {
	void *iov_base;   /* Starting address */
	size_t iov_len;   /* Number of bytes */
};

struct msghdr {
	void         * msg_name;     /* optional address */
	socklen_t    msg_namelen;    /* size of address */
	struct iovec * msg_iov;      /* scatter/gather array */
	size_t       msg_iovlen;     /* # elements in msg_iov */
	void         * msg_control;  /* ancillary data, see below */
	socklen_t    msg_controllen; /* ancillary data buffer len */
	int          msg_flags;      /* flags on received message */
};

#endif
