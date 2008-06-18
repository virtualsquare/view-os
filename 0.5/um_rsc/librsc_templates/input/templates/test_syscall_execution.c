<%#
     This is part of RSC file generator program
     
     test_syscall_execution.c: template file for system call execution tests.
     
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
<% @@librsc_relative_path = "tests/" %>
<% @@filename = "test_syscall_execution.c" %>
<% require "test_common_code.rb" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: system call execution tests 
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
#include <stdlib.h>
#include <stdio.h>
#include "rsc_client.h"
#include "rsc_server.h"
#include "test_rsc_server.h"

#define __USE_LARGEFILE64
#include "fill_request.h"
#include "fill_write_pointers.h"
#include "type_equality.h"
<%
  headers = []
  nr_all.each_umview { |syscall| headers << syscall.headers }
  headers.flatten!.sort!.uniq!.delete("utime.h")
  headers.collect!{ |hd| "#include <#{hd}>" }
%>
<%= headers.join("\n") %>



static void dump(void *p, int size, int bytenum) {
  int i;
  fprintf(stderr, "Mem %p[%d bytes]:", p, size);
  for(i = 0; i < size;  i++) {
    if(i % bytenum == 0)
      fprintf(stderr, "\n\t%p:\t", p+i);

    fprintf(stderr, "%.2X", 0xFF & *(char *)(p+i));
  }
  fprintf(stderr, "\n");
}

<% nr_all.each_umview do |syscall| %>
void client_test_<%=syscall.name%>(int fd) {
<%  if @@special_syscall[syscall.rsc] 
      @@special_syscall[syscall.rsc].each_with_index do |c, i| 
        str = "#ifdef #{c}"
        str = "#elif defined #{c}" if i != 0 %>
<%=str%> 
  return NULL;
<%    end %>
#else
<% end %>
  struct iovec *iov, *resp_iov;
  int nbytes, iov_count, ret;
  struct <%=syscall.name%>_req *in = fill_<%=syscall.name%>_request(<%=syscall.read_args.collect{|a| "FALSE"}.join(', ')%>);
  struct <%=syscall.name%>_req *local = fill_<%=syscall.name%>_request(<%=syscall.read_args.collect{|a| "FALSE"}.join(', ')%>);
  struct sys_resp_header resp_hd;

  /* I create the request with the data returned by fill_read_request() */
  iov = rscc_create_<%=syscall.name%>_request(&nbytes, &iov_count, <%= syscall.args.collect{|a| "in->#{a.name}"}.join(', ')%>);

  ret = writev(fd, iov, iov_count);
  assert(ret == nbytes);
  free(iov[0].iov_base); free(iov);
  ret = read(fd, &resp_hd, sizeof(struct sys_resp_header));
  assert(ret == sizeof(struct sys_resp_header));
  /* Now I call the manage response function */
  resp_iov = rscc_manage_<%=syscall.name%>_response(&resp_hd, &iov_count, &nbytes, <%= syscall.args.collect{|a| "in->#{a.name}"}.join(', ')%>);
<%  if syscall.has_write_args? %>
  assert(resp_iov != NULL); 
  ret = readv(fd, resp_iov, iov_count);
  assert(ret == nbytes);
  free(resp_iov);
  /* I fill the 'local' request, in this way I can compare this local copy with
   * the remote one 'in' */
  <%=syscall.name%>_fill_write_pointers(<%= syscall.args.collect{|a| "local->#{a.name}"}.join(', ')%>);
<%  else %>
  assert(resp_iov == NULL); 
<%  end %>
<%  syscall.args.each do |arg| %>
<%    if arg.type.pointer? %>
<%      if arg.type.type =~ /void \*/  %>
  assert(<%=compare_func_name(arg)%>(local-><%=arg.name%>, in-><%=arg.name%>, <%=arg.size("in->")%>));
<%      else %>
  assert(<%=compare_func_name(arg)%>(local-><%=arg.name%>, in-><%=arg.name%>));
<%      end %>
<%    else %>
<%      if arg.type.array?%>
<%          arg.type.array_size.times do |i| %>
  assert(<%=compare_func_name(arg)%>(&local-><%=arg.name%>[<%=i%>], &in-><%=arg.name%>[<%=i%>]));
<%          end %>
<%      else %>
  assert(local-><%=arg.name%> == in-><%=arg.name%>);
<%      end %>
<%    end %>
<%  end %>

  free_filled_<%=syscall.name%>_request(in, 0);
  free_filled_<%=syscall.name%>_request(local, 0);
<% if @@special_syscall[syscall.rsc] %>
#endif
<%  end %> 
}

void server_test_<%=syscall.name%>(int fd, enum arch server_arch, enum arch client_arch) {
<%  if @@special_syscall[syscall.rsc] 
      @@special_syscall[syscall.rsc].each_with_index do |c, i| 
        str = "#ifdef #{c}"
        str = "#elif defined #{c}" if i != 0 %>
<%=str%> 
  return NULL;
<%    end %>
#else
<% end %>
  int ret, req_size;
  struct sys_req_header *req_hd;
  struct sys_resp_header *resp_hd;
  struct <%=syscall.name%>_req *input = fill_<%=syscall.name%>_request(<%=syscall.read_args.collect{|a| "FALSE"}.join(', ')%>);
  struct <%=syscall.name%>_req * req;
  req_hd = calloc(1, sizeof(struct sys_req_header));
  assert(req_hd != NULL);
  ret = read(fd, req_hd, sizeof(struct sys_req_header));
  assert(ret == sizeof(struct sys_req_header));
  req_size = rsc_req_msg_size(req_hd);
  req_hd = realloc(req_hd, req_size);
  assert(req_hd != NULL);
  ret = read(fd, (void *)req_hd + sizeof(struct sys_req_header), req_size - sizeof(struct sys_req_header));
  assert(ret == req_size - sizeof(struct sys_req_header));
  

  req_hd->req_size = ntohl(req_hd->req_size);
  req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
  resp_hd = rscs_pre_<%=syscall.name%>_exec(req_hd, client_arch);
  req = (struct <%=syscall.name%>_req *) req_hd;
  /* I test the content of the request */
<%  syscall.args.each do |arg| %>
<%    # Only read pointers and non-pointer args can be checked 
      if not arg.write?  %>
<%      if arg.type.pointer? %>
<%        if arg.type.type =~ /void \*/  %>
  assert(<%=compare_func_name(arg)%>(req-><%=arg.name%>, input-><%=arg.name%>, <%=arg.size("input->")%>));
<%        else %>
  assert(<%=compare_func_name(arg)%>(req-><%=arg.name%>, input-><%=arg.name%>));
<%        end %>
<%      else %>
<%        if arg.type.array?%>
<%          arg.type.array_size.times do |i| %>
  assert(<%=compare_func_name(arg)%>(&req-><%=arg.name%>[<%=i%>], &input-><%=arg.name%>[<%=i%>]));
<%          end %>
<%        else %>
  assert(req-><%=arg.name%> == input-><%=arg.name%>);
<%        end %>
<%      end %>
<%    end %>
<%  end %>

<%  if syscall.has_write_args? %>
  /* I simulate the execution of the system call, calling
   * a function that fills the write pointer of the request. */
  ret = <%=syscall.name%>_fill_write_pointers(<%= syscall.args.collect{|a| "req->#{a.name}"}.join(', ')%>);
<%  else %>
  /* The syscall doesn't have write pointers, so I do nothing */
<%  end %>

  /* I call the post-execution function and then I send back the 
   * response. */
  resp_hd = rscs_post_<%=syscall.name%>_exec(req, resp_hd, ret, errno, client_arch);
  resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
  resp_hd->resp_size = htonl(resp_hd->resp_size);
  resp_hd->resp_retval = htonl(resp_hd->resp_retval);
  resp_hd->resp_errno = htonl(resp_hd->resp_errno);


  ret = write(fd, resp_hd, ntohl(resp_hd->resp_size));
  assert(ret == ntohl(resp_hd->resp_size));

  free(req); free(resp_hd); 
  free_filled_<%=syscall.name%>_request(input, 0);
<% if @@special_syscall[syscall.rsc] %>
#endif
<%  end %> 
}
<% end %>

/*******************************************************************/
/* Public test functions                                           */
/*******************************************************************/
void test_syscall_exec_client(int fd, enum arch myarch, enum arch sarch) {
<%  nr_all.each_umview do |syscall| %>
<%  if @@special_syscall[syscall.rsc] 
      cond =  @@special_syscall[syscall.rsc].collect{|c| 
        a = ""
        if(c == "__powerpc__")
          a = "ACONV_PPC"
        else
          a = "ACONV_X86_64"
        end
        "sarch != #{a}"
      }.join(" && ")
    %>
  if(<%=cond%>) 
    client_test_<%=syscall.name%>(fd);
<%    else %>
  client_test_<%=syscall.name%>(fd);
<%    end %>
<%  end %>
}

void test_syscall_exec_server(int fd, enum arch carch, enum arch myarch) {
<%  nr_all.each_umview do |syscall| %>
  server_test_<%=syscall.name%>(fd, myarch, carch);
<%  end %>
}
