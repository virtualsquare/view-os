<%#
     This is part of RSC file generator program
     
     server.c: template file for server side functions 
     
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
<% @@librsc_relative_path = "/src/" %>
<% @@filename = "rsc_server.c" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: server side functions 
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

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "rsc_server.h"
#include "utils.h"
#include "aconv.h"
#include "rsc_consts.h"
#include "generic_list.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>
<%
  headers = []
  nr_all.each_umview { |syscall| headers << syscall.headers }
  headers.flatten!.sort!.uniq!.delete("utime.h")
  headers.collect!{ |hd| "#include <#{hd}>" }
%>
<%= headers.join("\n") %>

static enum arch my_arch;
static struct list *ioctl_list;
/*########################################################################*/
/*##                                                                    ##*/
/*##  REQUEST FUNCTION DECLARATIONS and HANDLER TABLE                   ##*/
/*##                                                                    ##*/
/*########################################################################*/
typedef struct sys_resp_header *(*rscs_pre_exec)(void *req, enum arch client_arch);
typedef int (*rscs_exec)(void *request);
typedef struct sys_resp_header *(*rscs_post_exec)(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);

/* static void *req_func_recvmsg(void *req); */
<% nr_all.each_umview do |syscall| %>
struct sys_resp_header *rscs_pre_<%= syscall.name %>_exec(void *req, enum arch client_arch);
int rscs_exec_<%= syscall.name %>(void  *request);
struct sys_resp_header *rscs_post_<%= syscall.name %>_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
<% end %>
struct sys_resp_header *rscs_pre_ioctl_exec(void *req, enum arch client_arch);
int rscs_exec_ioctl(void  *request);
struct sys_resp_header *rscs_post_ioctl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fcntl_exec(void *req, enum arch client_arch);
int rscs_exec_fcntl(void  *request);
struct sys_resp_header *rscs_post_fcntl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);

/* Handler Tables */
rscs_pre_exec rscs_pre_exec_table[] = {
<%  nr_create_fun = ["ioctl", "fcntl"]
    nr_all.each_with_index { |syscall, i| 
      if(syscall.used_by_umview? or nr_create_fun.include?(syscall.name)) %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ rscs_pre_#{nr_all[i].name}_exec#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    else %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ NULL#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    end %>
<%  } %>
};

rscs_exec rscs_exec_table[] = {
<%  nr_create_fun = ["ioctl", "fcntl"]
    nr_all.each_with_index { |syscall, i| 
      if(syscall.used_by_umview? or nr_create_fun.include?(syscall.name)) %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ rscs_exec_#{nr_all[i].name}#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    else %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ NULL#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    end %>
<%  } %>
};

rscs_post_exec rscs_post_exec_table[] = {
<%  nr_create_fun = ["ioctl", "fcntl"]
    nr_all.each_with_index { |syscall, i| 
      if(syscall.used_by_umview? or nr_create_fun.include?(syscall.name)) %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ rscs_post_#{nr_all[i].name}_exec#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    else %>
  <%= "/* #{i}. #{nr_all[i].rsc} */ NULL#{i != (nr_all.length - 1) ? ',' : ""}\n" %>
<%    end %>
<%  } %>
};

/*########################################################################*/
/*##                                                                    ##*/
/*##  IOCTL MANAGEMENT                                                  ##*/
/*##                                                                    ##*/
/*########################################################################*/
struct ioctl_entry {
  int request; 
  u_int32_t size_type;
};

static int ioctl_entry_compare(void *e, void *request) {
  return ( ((struct ioctl_entry *)e)->request == *((int *)request));
}

#define ioctl_search(request) (list_search(ioctl_list, ioctl_entry_compare, &(request)))
#define ioctl_getel(index) ((struct ioctl_entry *)list_getel(ioctl_list, (index)))
#define free_ioctl_req(ioctl_req)   free(ioctl_req)

void rscs_ioctl_register_request(int request, u_int32_t rw, u_int32_t size) {
  struct ioctl_entry *req;
  req = calloc(1, sizeof(struct ioctl_entry));
  assert(req != NULL);
  req->request = request;
  req->size_type = rw | size;
  list_add(ioctl_list, req);
}


#ifndef RSCDEBUG
static
#endif
struct ioctl_resp_header *rscs_manage_ioctl_request(struct ioctl_req_header *ioctl_req) {
  struct ioctl_entry *res;
  struct ioctl_resp_header *resp;
  int index;
  resp = calloc(1, sizeof(struct ioctl_resp_header));
  assert(resp != NULL);
  
  ioctl_req->req_ioctl_request = ntohl(ioctl_req->req_ioctl_request);
  index = ioctl_search(ioctl_req->req_ioctl_request);
  res = ioctl_getel(index);

  /* I create the answer */
  resp->resp_type = RSC_IOCTL_RESP;
  resp->resp_size = htonl(sizeof(struct ioctl_resp_header));
  if(res == NULL) {
    /* Negative answer */
    resp->resp_size_type = htonl(IOCTL_UNMANAGED);
  } else {
    /* Positive one */
    resp->resp_size_type = htonl(res->size_type);
  }
  return resp;
}

/**************************************************************************/
/***  ADJUST READ POINTERS                                              ***/
/**************************************************************************/
<% nr_all.each_umview do |syscall| %>
<% if syscall.has_read_args? %>   
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void <%= syscall.name %>_adjust_read_pointers(struct <%= syscall.name %>_req *<%= syscall.name %>_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) <%= syscall.name %>_req) + sizeof(struct <%= syscall.name %>_req);
  <%  syscall.each_read_arg do |arg| 
        size = arg.size("#{syscall.name}_req->")  %> 
  if(<%= syscall.name %>_req-><%= arg.name %> != NULL) {
    <%= syscall.name %>_req-><%= arg.name %> = var_data;
    var_data += <%= size %>; 
  }
  <% end %> 
}
  <% end %>
<% end %>

# if 0
/* I need also of the resp structure because the space for the buffer that need to be
 * send back are allocated after it. */
static void recvmsg_adjust_read_pointers(struct recvmsg_req *recvmsg_req) {
  struct msghdr *msg;
  int i;
  void *var_data;
  msg = &(recvmsg_req->msg);

  /* "var_data" points to the next data to read */
  printf("msg = %p\n", msg);
  var_data = ((void *) recvmsg_req) + sizeof(struct recvmsg_req);
  printf("var_data: begin = %p\n", var_data);
  if(msg->msg_name != NULL) {
    msg->msg_name = var_data;
    var_data += msg->msg_namelen;
  }
  printf("var_data: after msg_name = %p\n", var_data);
  
  if(msg->msg_iov != NULL) {
    msg->msg_iov = calloc(msg->msg_iovlen, sizeof(struct iovec)); /*FIXME: maybe a control on the result of calloc? */
    for(i = 0; i < msg->msg_iovlen; i++) {
      (msg->msg_iov[i]).iov_len = *((size_t *)var_data);
      (msg->msg_iov[i]).iov_base = malloc((msg->msg_iov[i]).iov_len);
      var_data += sizeof((msg->msg_iov[i]).iov_len);
    }
  }
  printf("var_data: after msg_iov = %p\n", var_data);

  if(msg->msg_control != NULL)
    msg->msg_control = var_data;
  printf("var_data: after msg_control = %p\n", var_data);
}
#endif

/* Adjusts the read pointers of the request, the space pointed by them
 * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void ioctl_adjust_read_pointers(struct ioctl_req *ioctl_req, u_int32_t size_type) {
  void *var_data;

  if(ioctl_req->arg != NULL && (size_type & IOCTL_R)) {
    /* "var_data" points to the next data to read */
    var_data = ((void *) ioctl_req) + sizeof(struct ioctl_req);
    RSC_DEBUG(RSCD_REQ_RESP, "ioctl_req->arg = %p", var_data);
    ioctl_req->arg = var_data;
  }
}

/* Adjusts the read pointers of the request, the space pointed by them
 * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void fcntl_adjust_read_pointers(struct fcntl_req *fcntl_req) {
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK_R) {
    void *var_data;
    /* "var_data" points to the next data to read */
    var_data = ((void *) fcntl_req) + sizeof(struct fcntl_req);
   
    RSC_DEBUG(RSCD_REQ_RESP, "fcntl_req->third.lock = %p", var_data);
    if(fcntl_req->third.lock != NULL)
      fcntl_req->third.lock = var_data;
  }
}
/**************************************************************************/
/***  ADJUST WRITE POINTERS                                             ***/
/**************************************************************************/
<% nr_all.each_umview do |syscall| %>
<% if syscall.has_write_args? %>   
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void <%= syscall.name %>_adjust_write_pointers(struct <%= syscall.name %>_req *<%= syscall.name %>_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
<%  syscall.each_write_arg do |arg| %>
  if(<%=syscall.name%>_req-><%=arg.name%> != NULL) {
    if(my_arch == client_arch) {
<%    if(arg.read?) %>  
    /* '<%= syscall.name %>_req-><%= arg.name %>' contains the old value */
    memcpy(var_data, <%= syscall.name %>_req-><%= arg.name %>, <%= arg.size("#{syscall.name}_req->") %>);
<%    end  %> 
      <%= syscall.name %>_req-><%= arg.name %> = var_data;
      var_data += <%= arg.size("#{syscall.name}_req->") %>; 
    } else {
<%    if(not arg.read?) %>  
      <%= syscall.name %>_req-><%= arg.name %> = calloc(1, <%= aconv_size(arg, "my_arch", "client_arch", true, "#{syscall.name}_req->") %>);
      assert(<%= syscall.name %>_req-><%= arg.name %> != NULL);
<%    end %>
    }
      
  }
<%  end %> 
#if 0
  <%  syscall.each_write_arg do |arg| 
        size = arg.size("#{syscall.name}_req->")  %> 
  RSC_DEBUG(RSCD_REQ_RESP, "<%=syscall.name%>_req-><%=arg.name%> = %p", var_data);
  if(<%=syscall.name%>_req-><%=arg.name%> != NULL) {
  <%  # Is a value result argument?
      if(arg.read?) %>  
    /* '<%= syscall.name %>_req-><%= arg.name %>' contains the old value */
    memcpy(var_data, <%= syscall.name %>_req-><%= arg.name %>, <%= arg.size("#{syscall.name}_req->") %>);
  <%  end  %> 
    <%= syscall.name %>_req-><%= arg.name %> = var_data;
    var_data += <%= size %>; 
  }
  <% end %> 
#endif
}
  <% end %>
<% end %>

/* Adjusts the write pointers of the request, the space pointed by them
 * is stored in the response (in fact these informations are sent back to the client). 
 * Note: read/write pointers are sent by the client and have to be sent back to it after
 * the system call, this kind of arguments are usually called "value-result". So, for
 * these arguments, their content is copied from the request to the response, in this
 * way when the syscall change it, the new value resides already in the response. */
#ifndef RSCDEBUG
static 
#endif
void ioctl_adjust_write_pointers(struct ioctl_req *ioctl_req, struct sys_resp_header *resp_header, int resp_size, u_int32_t size_type, enum arch client_arch) {
  void *var_data;

  if(ioctl_req->arg != NULL && (size_type & IOCTL_W)) {
    var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
   
    RSC_DEBUG(RSCD_REQ_RESP, "ioctl_req->arg = %p", var_data);
    /* if 'ioctl_req->arg' is also a read pointer, I need to copy its content */
    if(size_type & IOCTL_R)
      memcpy(var_data, ioctl_req->arg, (size_type & IOCTL_LENMASK));
   
    ioctl_req->arg = var_data;
  }
   
}

/* Adjusts the write pointers of the request, the space pointed by them
 * is stored in the response (in fact these informations are sent back to the client). 
 * Note: read/write pointers are sent by the client and have to be sent back to it after
 * the system call, this kind of arguments are usually called "value-result". So, for
 * these arguments, their content is copied from the request to the response, in this
 * way when the syscall change it, the new value resides already in the response. */
#ifndef RSCDEBUG
static 
#endif
void fcntl_adjust_write_pointers(struct fcntl_req *fcntl_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;
  if( (fcntl_req->cmd_type & FCNTL_3RD_FLOCK_W) && (fcntl_req->third.lock != NULL)) {
    /* "var_data" points to the next data to read */
    var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
    RSC_DEBUG(RSCD_REQ_RESP, "fcntl_req->third.lock = %p", var_data);
    /* 'fcntl_req->third.lock' contains the old value */
    memcpy(var_data, fcntl_req->third.lock, sizeof(struct flock));
    fcntl_req->third.lock = var_data;
  }
}



/**************************************************************************/
/***  EXECUTION FUNCTIONS                                               ***/
/**************************************************************************/
<% nr_all.each_umview do |syscall| %>
struct sys_resp_header *rscs_pre_<%= syscall.name %>_exec(void *req, enum arch client_arch) {
  struct <%= syscall.name %>_req *<%= syscall.name %>_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  <%= syscall.name %>_req = (struct <%= syscall.name %>_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(<%= syscall.name %>_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(<%=syscall.name%>_req),
      rsc2str(<%=syscall.name%>_req->req_rsc_const), <%=syscall.name%>_req->req_rsc_const,
      <%=syscall.name%>_req->req_type, <%=syscall.name%>_req->req_type, 
      <%=syscall.name%>_req->req_size, <%=syscall.name%>_req->req_size);

  if(<%= syscall.name %>_req->req_size < sizeof(struct <%= syscall.name %>_req))
    return NULL;

  <% list_str = syscall.args.collect {|arg| "#{arg.name} = #{arg.type.printf_conv_spec} (0x%lX)"} 
     list_arg = syscall.args.collect { |arg| name = "#{syscall.name}_req->#{arg.name}"; [name, name] }.flatten%>  
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: <%= list_str.join('; ') %>", <%= list_arg.join(', ')%>);

  <% if syscall.has_read_args? %> 
  /* Adjusts the read pointers of the request */
  <%= syscall.name %>_adjust_read_pointers(<%= syscall.name %>_req);
  <% end %>

  resp_size = sizeof(struct sys_resp_header);
<%  syscall.write_args.each do |arg| %>
  if(<%=syscall.name%>_req-><%=arg.name%> != NULL) {
<%    # If the size is a var, I use it for the right size of the buffer
        if(arg.is_size_a_var?) %>
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by '<%=arg.size_var.name%>' argument. */
<%      if(arg.is_size_a_var?)
          if(arg.type.pointer? and (arg.type.type !~ /void \*/ or arg.type.type !~ /char \*/)) %>
    /* The client can have changed the value of <%=arg.size_var %> if it was less than
     * the size of <%=arg.name%> into server arch. So If <%=arg.size_var %> is equal
     * to this value I need to change it to the right value on client arch. */
    if(<%=arg.size("#{syscall.name}_req->")%> == <%=aconv_size(arg, "client_arch", "my_arch", true, "#{syscall.name}_req->")%>) {
      resp_size += <%=aconv_size(arg, "my_arch", "client_arch", true, "#{syscall.name}_req->")%>;
    } else {
      resp_size += <%=arg.size("#{syscall.name}_req->")%>; 
    }
<%        else %>
    resp_size += <%=arg.size("#{syscall.name}_req->")%>;
<%        end
        end %>
<%      else  %>
    resp_size += <%=aconv_size(arg, "my_arch", "client_arch", true, "#{syscall.name}_req->")%>; 
<%      end %>
  }
<%  end %>
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

  <% if syscall.has_write_args? %> 
  /* Adjusts the write pointers of the request */
  <%= syscall.name %>_adjust_write_pointers(<%= syscall.name %>_req, resp_header, resp_size, client_arch);
  <% end %> 
  RSC_EXDUMP(RSCD_REQ_RESP, <%=syscall.name%>_req, <%=syscall.name%>_req->req_size);

  /* resp_header->resp_type = <%= syscall.name %>_req->req_type; */
  resp_header->resp_rsc_const = <%= syscall.name %>_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_<%= syscall.name %>(void  *request) {
  int ret;
  struct <%= syscall.name %>_req *req = (struct <%= syscall.name %>_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
  <% 
    args_list = syscall.args.collect{|arg| "req->#{arg.name}"}
    # The syscall statfs64 and fstatfs64 takes and additional argument when
    # called with syscall(). This argument is the sizeof the struct statfs64,
    # and is not present in the statfs64()/fstatfs64() functions. 
    if(syscall.rsc == "__RSC_statfs64" || syscall.rsc == "__RSC_fstatfs64")
      args_list.insert(1, "sizeof(struct statfs64)")
    end
  %>
  <% if syscall.sys.nil? %> 
  ret = syscall(nr_and_sys->nr, <%= args_list.join(', ') %>);
  <% else %> 
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, <%= args_list.join(', ') %>);
#else
      <% args_list = args_list.collect{|arg| "(unsigned long)(#{arg})"}  %> 
    {
	    unsigned long args[] = { <%= args_list.join(",\n\t\t\t") %> };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  <% end %>

  return ret;
}

struct sys_resp_header *rscs_post_<%= syscall.name %>_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
<%  if syscall.has_write_args?  %>
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct <%= syscall.name %>_req *<%= syscall.name %>_req = (struct <%= syscall.name %>_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
<%    syscall.write_args.each do |arg|  %>
    <%=aconv(arg, "my_arch", "client_arch", "mem", true, "#{syscall.name}_req->") %>;
    mem += <%=aconv_size(arg, "my_arch", "client_arch", true, "#{syscall.name}_req->")%>;
<%    # If it's not a value-result argument, I need to free it  
        if(not arg.read?) %>
    free(<%= syscall.name %>_req-><%=arg.name%>);
<%      end %>
<%    end %>
  }
<%  end %>
  <%  has_size_retval = syscall.write_args.inject(false) {|val, arg| val ||= arg.size_retval? } 
      if(has_size_retval)
        size_list = syscall.write_args.select{|arg| !arg.size_retval?} 
        write_args_retval = syscall.write_args.select{|arg| arg.size_retval?}%>  
  /* If the right size of the buffer is returned by the system call, 
   * I use it to send back only the part of the buffer with data */
  /* resp->resp_size = sizeof(struct sys_resp_header); */
<%  size_list.each do |arg| %>
  if(<%=syscall.name%>_req != NULL)
    resp->resp_size += <%=arg.size("#{syscall.name}_req->")%>;
<%  end %>
  /* Note: I suppose that the buffer is the last data into the response, 
   * So I can subtract the unused buffer space, otherwise this doesn't 
   * work. */
  if( resp->resp_retval >= 0 ) {
<%  write_args_retval.each do |arg| %>
    if(((struct <%=syscall.name%>_req *)req)-><%=arg.name%> != NULL)
      resp->resp_size -= (<%=arg.size("((struct #{syscall.name}_req *)req)->")%> - resp->resp_retval);
<%  end %>
  }
<%  end%> 
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

<% end %>

struct sys_resp_header *rscs_pre_ioctl_exec(void *req, enum arch client_arch) {
  struct ioctl_req *ioctl_req;
  struct sys_resp_header *resp_header;
  int resp_size, index;
  struct ioctl_entry *ioctle;

  ioctl_req = (struct ioctl_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(ioctl_req->req_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(ioctl_req),
      rsc2str(ioctl_req->req_rsc_const), ioctl_req->req_rsc_const,
      ioctl_req->req_type, ioctl_req->req_type, 
      ioctl_req->req_size, ioctl_req->req_size);

  if(ioctl_req->req_size < sizeof(struct ioctl_req))
    return NULL;

  index = ioctl_search(ioctl_req->request);
  ioctle = ioctl_getel(index);
  assert(ioctle != NULL);

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: d = %ld (0x%lX); request = %ld (0x%lX); arg = %p (0x%lX)", 
      ioctl_req->d, ioctl_req->d, ioctl_req->request, ioctl_req->request, ioctl_req->arg, ioctl_req->arg);

  /* Adjusts the read pointers of the request */
  ioctl_adjust_read_pointers(ioctl_req, ioctle->size_type);
  
  resp_size = sizeof(struct sys_resp_header);
  if(ioctl_req->arg != NULL && (ioctle->size_type & IOCTL_W))
    resp_size += ioctle->size_type & IOCTL_LENMASK;
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  ioctl_adjust_write_pointers(ioctl_req, resp_header, resp_size, ioctle->size_type, client_arch);
  
  /* resp_header->resp_type = ioctl_req->req_type; */
  resp_header->resp_rsc_const = ioctl_req->req_rsc_const;

  return resp_header;

}  
int rscs_exec_ioctl(void  *request) {
  int ret;
  struct ioctl_req *req = (struct ioctl_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
  ret = syscall(nr_and_sys->nr, req->d, req->request, req->arg);

  return ret;
}
    
struct sys_resp_header *rscs_post_ioctl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fcntl_exec(void *req, enum arch client_arch) {
  struct fcntl_req *fcntl_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fcntl_req = (struct fcntl_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fcntl_req->req_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fcntl_req),
      rsc2str(fcntl_req->req_rsc_const), fcntl_req->req_rsc_const,
      fcntl_req->req_type, fcntl_req->req_type, 
      fcntl_req->req_size, fcntl_req->req_size);

  if(fcntl_req->req_size < sizeof(struct fcntl_req))
    return NULL;
    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); cmd = %ld (0x%lX);", fcntl_req->fd, fcntl_req->fd, fcntl_req->cmd, fcntl_req->cmd);

  resp_size = sizeof(struct sys_resp_header);
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK_W)
    resp_size += sizeof(struct flock);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

  /* If there is a third argument and it is a 'struct flock' pointer */
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK) {
    /* Adjusts the read pointers of the request */
    fcntl_adjust_read_pointers(fcntl_req);
   
    /* Adjusts the write pointers of the request */
    fcntl_adjust_write_pointers(fcntl_req, resp_header, resp_size, client_arch);
  }
  
  resp_header->resp_rsc_const = fcntl_req->req_rsc_const;

  return resp_header;
}
int rscs_exec_fcntl(void  *request) {
  int ret;
  struct fcntl_req *req = (struct fcntl_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);

  if(req->cmd_type & FCNTL_NO_3RD_ARG) {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd);
  } else if(req->cmd_type & FCNTL_3RD_LONG) {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd, req->third.arg);
  } else {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd, req->third.lock);
  }

  return ret;  
} 

struct sys_resp_header *rscs_post_fcntl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}
/*########################################################################*/
/*##                                                                    ##*/
/*##  REQUEST MANAGEMENT                                                ##*/
/*##                                                                    ##*/
/*########################################################################*/

#if 0
void *req_func_recvmsg(void *req) {
	struct recvmsg_req *recvmsg_req;
  struct recvmsg_resp *recvmsg_resp;
  struct nr_and_sys *nr_and_sys;
  void *data, *new_ptr;
  int read_buffer_size, i;
  
  recvmsg_req = (struct recvmsg_req *) req;
  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s (%p):", rsc2str(recvmsg_req->req_type), recvmsg_req);
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: req_type = %d (0x%X); req_size = %d (0x%X) bytes", recvmsg_req->req_type, recvmsg_req->req_type, recvmsg_req->req_size, recvmsg_req->req_size);
  
	RSC_DEBUG(RSCD_REQ_RESP, "\ts = %ld; msg = * ; flags = %ld", recvmsg_req->s, recvmsg_req->flags);
  
  recvmsg_adjust_read_pointers(recvmsg_req);
  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, &(recvmsg_req->msg));
	
	recvmsg_resp = malloc(sizeof(struct recvmsg_resp));
	if(recvmsg_resp == NULL)
	  return NULL;
  bzero(recvmsg_resp, sizeof(struct recvmsg_resp));
	
	recvmsg_resp->resp_type = recvmsg_req->req_type;

  if( (nr_and_sys = rsc2nr(recvmsg_req->req_type, my_arch)) == NULL)
    return NULL;
	{
		unsigned long args[] = {(unsigned long)(recvmsg_req->s), (unsigned long)(&(recvmsg_req->msg)), (unsigned long)(recvmsg_req->flags)};
		recvmsg_resp->resp_retval = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
	}
	recvmsg_resp->resp_errno = errno;
  /* I need to add the buffers read  */
  read_buffer_size = 0;
  if(recvmsg_resp->resp_retval > 0) {
    for(i = 0; i < recvmsg_req->msg.msg_iovlen; i++)
      read_buffer_size += recvmsg_req->msg.msg_iov[i].iov_len;
  } 
	recvmsg_resp->resp_size = sizeof(struct recvmsg_resp) + read_buffer_size;
  if(recvmsg_req->msg.msg_control != NULL)
	  recvmsg_resp->resp_size += recvmsg_req->msg.msg_controllen;
  
  if((new_ptr = realloc(recvmsg_resp, recvmsg_resp->resp_size)) == NULL)
    return NULL;
  recvmsg_resp = new_ptr;
  data = ((void *)recvmsg_resp) + sizeof(struct recvmsg_resp);
  for(i = 0; i < recvmsg_req->msg.msg_iovlen; i++) {
    memcpy(data, recvmsg_req->msg.msg_iov[i].iov_base, recvmsg_req->msg.msg_iov[i].iov_len);
    data += recvmsg_req->msg.msg_iov[i].iov_len;
  }

  if(recvmsg_req->msg.msg_control != NULL)
    memcpy(data, recvmsg_req->msg.msg_control, recvmsg_req->msg.msg_controllen);
  
  recvmsg_resp->msg_controllen = recvmsg_req->msg.msg_controllen;
    
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s (%p):", rsc2str(recvmsg_resp->resp_rsc_const), recvmsg_resp);
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: resp_type = %d (0x%X); resp_size = %d (0x%X) bytes; resp_retval = %d (0x%X); resp_errno = %d (0x%X)", recvmsg_resp->resp_type, recvmsg_resp->resp_type, recvmsg_resp->resp_size, recvmsg_resp->resp_size, recvmsg_resp->resp_retval, recvmsg_resp->resp_retval, recvmsg_resp->resp_errno, recvmsg_resp->resp_errno);
  return recvmsg_resp;
}
#endif

/*########################################################################*/
/*##                                                                    ##*/
/*##  PUBLIC FUNCTIONS                                                  ##*/
/*##                                                                    ##*/
/*########################################################################*/

int rscs_init(enum arch server_arch) {
  my_arch = server_arch;
  ioctl_list = init_list(100);
  if(ioctl_list == NULL)
    return -1;

  return 0;
}

void rsc_server_teardown() {
  my_arch = ACONV_ARCH_ERROR;
  teardown_list(ioctl_list, free);
  ioctl_list = NULL;
}

void *rscs_manage_request(int client_arch, void *request) {
  void *ret_data;
  struct req_header *req_hd;
 
  req_hd = (struct req_header *)request;
  req_hd->req_size = ntohl(req_hd->req_size);
  if( req_hd->req_type == RSC_IOCTL_REQ) {
	  RSC_DEBUG(RSCD_REQ_RESP,"RSC IOCTL Request management");
    ret_data = rscs_manage_ioctl_request((struct ioctl_req_header *)request);
  } else if( req_hd->req_type == RSC_SYS_REQ) {
    struct sys_req_header *req_hd;
    struct sys_resp_header *resp_hd;
    rscs_pre_exec pre_exec_f;
    int ret;
    rscs_exec exec_f;
    rscs_post_exec post_exec_f;
    req_hd = (struct sys_req_header *)request;
    /* I convert the filed of the RSC SYS request header */ 
    req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
	  RSC_DEBUG(RSCD_REQ_RESP,"RSC SYS Request management: %X(%s)", req_hd->req_rsc_const, rsc2str(req_hd->req_rsc_const));
    if( req_hd->req_rsc_const < __RSC_FIRST || req_hd->req_rsc_const > __RSC_LAST )
      return NULL;
    pre_exec_f = rscs_pre_exec_table[req_hd->req_rsc_const];
    exec_f = rscs_exec_table[req_hd->req_rsc_const];
    post_exec_f = rscs_post_exec_table[req_hd->req_rsc_const];
    if(pre_exec_f == NULL || exec_f == NULL || post_exec_f == NULL)
      return NULL;
    if((resp_hd = pre_exec_f(request, client_arch)) == NULL)
      return NULL;
    ret = exec_f(request);
    resp_hd = post_exec_f(request, resp_hd, ret, errno, client_arch);

    /* I convert the response's header fields */ 
    resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
    resp_hd->resp_size = htonl(resp_hd->resp_size);
    resp_hd->resp_retval = htonl(resp_hd->resp_retval);
    resp_hd->resp_errno = htonl(resp_hd->resp_errno);
    ret_data = resp_hd;
  } else {
    /* Bad request type */
    ret_data = NULL;
  }

  return ret_data;
}

