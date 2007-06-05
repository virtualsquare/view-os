<%#
     This is part of RSC file generator program
  
     client.h: template file for client side functions header
     
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
<% @@librsc_relative_path = "/include/" %>
<% @@filename = "rsc_client.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: client side functions header
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
#ifndef __RSC_CLIENT_HEADER__
#define __RSC_CLIENT_HEADER__

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include "aconv.h"
#include "rsc_messages.h"
#include "rsc_consts.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
<%
  headers = []
  nr_all.each_umview { |syscall| headers << syscall.headers }
  headers.flatten!.sort!.uniq!.delete("utime.h")
  headers.collect!{ |hd| "#include <#{hd}>" }
%>
<%= headers.join("\n") %>

/*************************************************/
/*   CALLBACK REGISTRATION STRUCTURES            */
/*************************************************/
struct reg_cbs {
  struct reg_cb *v;
  int size;
  int nentry;
};

struct reg_cb {
  int fd;
  int how;
  void (* cb)();
  void *arg;
  /* Added to patch the event subscribe loop problem */
  int ack; /* Is the value of the ACK received. It's initialized to -1  */
  int cb_executed; /* True if the callback has been already executed, false otherwise */
};


/*************************************************/
/*   INIT FUNCTION                               */
/*************************************************/
int rscc_init(int client_fd, int event_sub_fd, struct reg_cbs **rc, enum arch c_arch, enum arch s_arch);


/*************************************************/
/*   EVENT SUBSCRIPTION                          */
/*************************************************/
struct reg_cbs *rscc_es_init(int event_sub_fd);
int rscc_es_send_req(struct reg_cbs *reg_cbs, int server_fd, int event_sub_fd, int how, void (* cb)(), void *arg);


/*************************************************/
/*   INTERFACE 1: rscc functions                 */
/*************************************************/

<% nr_all.each_umview do |syscall| %>
int rscc_<%= syscall.name %>(<%= syscall.args.join(', ')%>);
<% end %>
int rscc_ioctl(int d, int request, void *arg);
int rscc_fcntl(int fd, int cmd, ...);

/*************************************************************/
/*   INTERFACE 2: create_request/manage_response functions   */
/*************************************************************/
<% nr_all.each_umview do |syscall| %>
struct iovec *rscc_create_<%= syscall.name %>_request(int *total_size, int *iovec_count, <%= "#{syscall.args.join(', ')}" %>);
struct iovec *rscc_manage_<%=syscall.name%>_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, <%= syscall.args.join(', ')%>);
<% end %>
struct iovec *rscc_create_fcntl_request(int *total_size, int *iovec_count, u_int16_t cmd_type, int fd, int cmd, long third_arg);
struct iovec *rscc_manage_fcntl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int16_t cmd_type, long third_arg);

u_int32_t rscc_check_ioctl_request(int request);
struct iovec *rscc_create_ioctl_request(int *total_size, int *iovec_count, u_int32_t size_type, int d, int request, void *arg);
struct iovec *rscc_manage_ioctl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int32_t size_type, void *arg);
#endif /* __RSC_CLIENT_HEADER__ */
