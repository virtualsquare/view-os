<%#
     This is part of RSC file generator program
  
     testing_tools_fill_request.h: template file for the header of the 
                                   fill RSC request functions used by tests 
     
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
<% @@librsc_relative_path = "/tests/tools/" %>
<% @@filename = "fill_request.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: header of the fill RSC request functions used by tests 
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

#ifndef __FILL_REQUEST_HEADER__
#define __FILL_REQUEST_HEADER__
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <string.h>

#include "rsc_client.h"

#define FALSE 0
#define TRUE  1


struct sockaddr_in *fill_struct_sockaddr_in(void);
char *fill_string(char *str);

/**********************************************************/
/* Fill request                                           */
/**********************************************************/
<%  nr_all.each_umview do |syscall| 
      if(syscall.has_read_args?)
%>
struct <%=syscall.name%>_req *fill_<%=syscall.name%>_request(<%=syscall.read_args.collect{|arg| "int #{arg.name}_null"}.join(', ')%>);
<%   else %>
struct <%=syscall.name%>_req *fill_<%=syscall.name%>_request(void);
<%    end 
    end
%>

#define FILL_IOCTL_R    0x1  
#define FILL_IOCTL_W    0x2
#define FILL_IOCTL_RW   (FILL_IOCTL_R | FILL_IOCTL_W)
struct ioctl_req *fill_ioctl_request(int arg_null, int how);
struct fcntl_req *fill_fcntl_request(u_int16_t cmd_type, int lock_null);
/**********************************************************/
/* Free filled request                                    */
/**********************************************************/
<%  nr_all.each_umview do |syscall| %>
void free_filled_<%=syscall.name%>_request(struct <%=syscall.name%>_req *req, int only_pointed_memory);
<%  end %>
void free_filled_fcntl_request(struct fcntl_req *req, int only_pointed_memory);
void free_filled_ioctl_request(struct ioctl_req *req, int only_pointed_memory);
#endif /* __FILL_REQUEST_HEADER__ */
