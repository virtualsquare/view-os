<%#
     This is part of RSC file generator program
  
     server_tests.h: template file for the header containing private 
                     server side functions to be tested
     
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
<% @@filename = "test_rsc_server.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: header containing private server side functions to be tested
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
#ifndef __RSC_SERVER_TESTS_H__
#define __RSC_SERVER_TESTS_H__


#ifdef RSCDEBUG
#include "rsc_messages.h"
struct ioctl_resp_header *rscs_manage_ioctl_request(struct ioctl_req_header *ioctl_req);

<%  nr_all.each_umview do |syscall| 
      if(syscall.has_read_args?)  %>
void <%= syscall.name %>_adjust_read_pointers(struct <%= syscall.name %>_req *<%= syscall.name %>_req);
<%    end 
    end%>

<%  nr_all.each_umview do |syscall| 
      if(syscall.has_write_args?)  %>
void <%= syscall.name %>_adjust_write_pointers(struct <%= syscall.name %>_req *<%= syscall.name %>_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
<%    end 
    end%>
<%  nr_all.each_umview do |syscall|  %>
struct sys_resp_header *rscs_pre_<%= syscall.name %>_exec(void *req, enum arch client_arch);
int rscs_exec_<%= syscall.name %>(void  *request);
struct sys_resp_header *rscs_post_<%= syscall.name %>_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
<%  end %>
#endif /* RSCDEBUG */
#endif /* __RSC_SERVER_TESTS_H__ */
