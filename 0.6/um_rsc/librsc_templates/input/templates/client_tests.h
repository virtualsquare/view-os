<%#
     This is part of RSC file generator program
  
     client_tests.h: template file for the header containing private client 
                     side functions to be tested
     
     Copyright (C) 2007 Andrea Forni
     
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License, version 2, as
     published by the Free Software Foundation.
  
     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.
  
     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
%>
<% @@librsc_relative_path = "/src/include/" %>
<% @@filename = "test_rsc_client.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: header containing private client side functions to be tested
 *   
 *   Copyright (C) 2007 Andrea Forni
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
 */
#ifndef __TEST_RSC_CLIENT_HEADER__
#define __TEST_RSC_CLIENT_HEADER__

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include "rsc_client.h"

#ifdef RSCDEBUG
struct ioctl_cache_el {
  int request;
  u_int32_t size_type;
  struct ioctl_cache_el *prev;
  struct ioctl_cache_el *next;
};

struct ioctl_cache {
  struct ioctl_cache_el *first;
  struct ioctl_cache_el *last;
  int size;
  int nentry;
};

struct ioctl_cache *ioctl_cache;
struct ioctl_cache *ioctl_cache_init(int size);
void ioctl_cache_add(struct ioctl_cache *cache, int request, u_int32_t size_type);
u_int32_t ioctl_cache_search(struct ioctl_cache *cache, int request);
u_int16_t fcntl_cmd_type(int cmd);
#endif
#endif /* __TEST_RSC_CLIENT_HEADER__ */
