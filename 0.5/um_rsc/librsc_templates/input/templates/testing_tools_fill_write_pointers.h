<%#
     This is part of RSC file generator program
  
     testing_tools_write_pointers.h: template file for the header of the 
            functions used during the tests to fill write syscall buffers 
     
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
<% @@filename = "fill_write_pointers.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: header of the functions used during the tests 
 *   to fill write syscall buffers 
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
#ifndef  __FILL_WRITE_POINTERS__
#define  __FILL_WRITE_POINTERS__
#include <stdlib.h>
#include <stdio.h>

#include "rsc_client.h"

<%
  headers = []
  nr_all.each_umview { |syscall| headers << syscall.headers }
  headers.flatten!.sort!.uniq!.delete("utime.h")
  headers.collect!{ |hd| "#include <#{hd}>" }
%>
<%= headers.join("\n") %>


int simple_fill();

<%  nr_all.each_umview do |syscall| %>
<%    if(syscall.has_write_args?) %>
int <%=syscall.name%>_fill_write_pointers(<%=syscall.args.join(', ')%>);
<%    end %>
<%  end %>
int ioctl_fill_write_pointers(int d, int request, void *arg);
int fcntl_fill_write_pointers(int16_t cmd_type, int fd, int cmd, struct flock *lock);

#endif /* __FILL_WRITE_POINTERS__ */
