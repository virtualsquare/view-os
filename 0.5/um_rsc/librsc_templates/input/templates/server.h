<%#
     This is part of RSC file generator program
  
     server.h: template file for server side functions header
     
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
<% @@filename = "rsc_server.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: server side functions header
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
#ifndef __RSC_SERVER_REQ_RESP_H__
#define __RSC_SERVER_REQ_RESP_H__

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include "aconv.h"
#include "rsc_messages.h"
#include "rsc_consts.h"

#define CONN_OK                  0
#define CONN_ERROR              -1
#define CONN_CLOSED             -2
#define CONN_HANDLER_NOT_FOUND  -3
#define CONN_BAD_REQ_TYPE       -4

int rscs_init(enum arch server_arch);
void rsc_server_teardown();
struct iovec*rscs_manage_request(int client_arch, void *request);

/* Ioctl request registration */
void rscs_ioctl_register_request(int request, u_int32_t rw, u_int32_t size);

/*************************************************/
/*   EVENT SUBSCRIPTION                          */
/*************************************************/
struct rsc_es_ack *rscs_es_manage_msg(int esfd, void *data);
struct rsc_es_resp *rscs_es_event_occured(int esfd, int mfd, int event);
#endif /* __RSC_SERVER_REQ_RESP_H__ */
