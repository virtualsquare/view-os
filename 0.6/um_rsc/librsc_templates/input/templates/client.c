<%#
     This is part of RSC file generator program
  
     client.c: template file for client side functions 
     
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

<%# These first two lines initialize two global variable used by the stub controller 
  # to know:
  # - the relative path respect the base directory taken in input by the compiler
  # - the output filename
  # For example the output file of this template must be saved as "src/rsc_client.c". %>
<% @@librsc_relative_path = "/src/" %>
<% @@filename = "rsc_client.c" %>
<%# This instruction includes an external Ruby file, it's like the C #include directive %>
<% require "common_code.rb" %>

<%# This is the license of the outputted file %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: client side functions 
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include "registered_callbacks.h"
#include "debug.h"
#include "utils.h"
#include "rsc_client.h"
#include "rsc_consts.h"
#include "event_sub.h"

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <stdarg.h>


<%# Creates the list of headers "header".  %>
<%
  headers = []
  # For each system call, its header list is added to "headers" array
  nr_all.each_umview { |syscall| headers << syscall.headers }

  # headers is now an "array of array", the "flatten!" method transforms "headers"
  # in a flatted array. Then its contents are sorted, the duplicates and 
  # "utime.h" header are removed (this header is removed for some conflicts created
  # by the inclusion of another header defining the same data types.)
  headers.flatten!.sort!.uniq!.delete("utime.h")

  # Each entry inside "headers" is transformed into the C string: "#include <header name>"
  headers.collect!{ |hd| "#include <#{hd}>" }
%>
<%# The content of "header" is output in the final file, after each entry a '\n' is outputted %>
<%= headers.join("\n") %>

<%# This is normal C code, outputted as is into the final file %>
#ifndef RSCDEBUG
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
#else
#include "test_rsc_client.h"
#endif

#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache_init(int size);


static enum arch my_arch;
static enum arch server_arch;
static int rsc_sockfd;
static int rsc_event_sub_fd;
#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache;

int rscc_init(int client_fd, int event_sub_fd, struct reg_cbs **rc, enum arch c_arch, enum arch s_arch) {
  if(c_arch < ARCH_FIRST || c_arch > ARCH_LAST) 
    return -1;
  if(s_arch < ARCH_FIRST || s_arch > ARCH_LAST) 
    return -1;

  rsc_sockfd = client_fd;
  my_arch = c_arch;
  server_arch = s_arch;
  rsc_event_sub_fd = event_sub_fd;
  /* I init the event subscribe sub-module if there is a valid fd */
  if(event_sub_fd >= 0 && rc != NULL)  {
    if((*rc = rscc_es_init(event_sub_fd)) == NULL)
      return -1;
  }

  /* I init the ioctl cache */
  ioctl_cache = ioctl_cache_init(20);
  if(ioctl_cache == NULL)
    return -1;
  return 0;
}

/*########################################################################*/
/*##                                                                    ##*/
/*##  Remote System Call FUNCTIONS - Client side                        ##*/
/*##                                                                    ##*/
/*########################################################################*/


/*##########################################################*/
/*##                                                      ##*/
/*##  REQUEST CREATION FUNCTIONS                          ##*/
/*##                                                      ##*/
/*##########################################################*/
<%# From here stats the main loop. The stub compiler provides to each template an array called "nr_all", 
  # containing all the system calls gathered from the parsing of the four unistd.h files. The class of
  # "nr_all" is Syscall::ConstantList.
  # The method "each_umview" is an iterator, it iterates over the only system call supported by UMView;
  # the list of these system call is provided by the parsing of the IDL file.
  # Inside the block of the iterator (after the "do" keyword) the current system call is provided; its
  # class is Syscall::Constant.
  # In conclusion, the list of all the system call supported by UMView is iterated, for each iteration 
  # the current element ("syscall") is provided inside the block %>

<% nr_all.each_umview do |syscall| %>
<%# This is an example of the use of the syscall object: the system call name is
  # generate inside a C comment%>
/* This function build the request for the system call '<%= syscall.name %>' */
<%# Here the system call name is used to generate the name of the specific function.
  # The "syscall.args" expression returns the system call specific arguments, they are joined by a comma and outputted into
  # the function argument list %>
struct iovec *rscc_create_<%= syscall.name %>_request(int *total_size, int *iovec_count, <%= syscall.args.join(', ') %>) {
  struct <%=syscall.name%>_req *req;
  enum rsc_constant rsc_const;
  int req_size;
<%# If the system call has some read pointer arguments, the "int i" is defined %>
<%  if syscall.has_read_args? %>
  int i;
<%  end %>
  struct iovec *v;
  size_t vcount;

<%# This was a hack added recently. @@special_syscall is a hash table defined into the
  # "common_code.rb" file, they keys are the __RSC_* constants of some system calls 
  # not supported in all the architectures, they values are arrays listing in which 
  # architectures the system call is NOT supported.
  # If the syscall.rsc constant is defined inside the hash table, the following code 
  # generates a string saved inside the variable "cond". This string is a set of 
  # or-separated equality tests. %>
<%  # Tests if the syscall.rsc constant is defined inside the hash table
    if @@special_syscall[syscall.rsc] 
    cond =  @@special_syscall[syscall.rsc].collect { |cost|
              # Each constant inside the array associated with the "syscall.rsc" key
              # is converted into the correspondent LibAConv architecture constant
              if cost == "__powerpc__"
                next "ACONV_PPC"
              elsif cost == "__x86_64__"
                next "ACONV_X86_64"
              elsif cost == "__powerpc64__"
                next "ACONV_PPC_64"
              end
              # The next collect transforms the constant into an equality, and these 
              # equalities are joined by an "or" operator.
              }.collect{|aconv| "server_arch == #{aconv}"}.join(" || ")
  %>
  /* If the destination architecture doesn't support this syscall, I return immediately */
  <%# Print the conditions inside the "if" %> 
  if(<%=cond %>)
    return NULL;
<%  end %>

<%# Here there is some code to manage the read pointer arguments, if they exist. %>
<%  if syscall.has_read_args?
      ### If the system call has some read pointers, I define one auxiliary C variable
      ### for each of them; the name of these variables is:  
      ### <original name of the variable containing the size of the pointed read memory>_value
      ### These variables are defined to manage NULL read pointers.

      # I iterate over the read pointers
      syscall.read_args.each do |arg| 
      # I define the variable only of those pointer for which 
      # there is a variable containing their size. 
      # The method "is_size_a_var?" returns true if exists for the given 
      # read pointer argument "arg" a "size variable"
        if(arg.is_size_a_var?) 
          # If the "size variable" is a pointer, it's necessary to remove the '*' character
          # from the type outputted. For this reason there is an if, and in the true-branch 
          # there is a "sub(/\*/, '')" is called; The "strip" method removes the 
          # leading and trailing white spaces.
          if(arg.size_var.type.pointer?) %> 
  <%= arg.size_var.type.type.sub(/\*/, '').strip%> <%=arg.size_var.name%>_value;
<%        else %>
  <%= arg.size_var.type.type %> <%=arg.size_var.name%>_value;
<%        end %>
<%      else %>
  <%# If "arg" has not a "size variable" (maybe "arg" is a string), a int variable is defined %>
  int <%=arg.name%>_size_value;
<%      end
      end  # end of "syscall.read_args.each do |arg|" %>
<%
      ### If the pointed memory size is contained in another variable, which is a pointer 
      ### and this pointer is NULL, there is an error.
      syscall.args.each do |arg| 
        if(arg.type.pointer? && arg.is_size_a_var? && arg.size_var.type.pointer?) %>
  /* The size of '<%=arg.name%>' is contained in the memory pointed by '<%=arg.size_var.name%>',
   * but if the latter is NULL I cannot know the size of '<%=arg.name%>'. */
  if(<%=arg.name%> != NULL && <%=arg.size_var.name%> == NULL)
    return NULL;
<%
        end
      end
    end # end of "if syscall.has_read_args?"
%>
  

  req_size = sizeof(struct <%=syscall.name%>_req);
  /* If the server and mine architectures are different, I need to calculate the 
   * total request size adding the size of each argument type in the server architecture. */
  if(my_arch != server_arch) {
    req_size = sizeof(struct sys_req_header);

<%# For each argument, I call the function "aconv_size" defined into "common_code.rb" file.
  # This function returns a string with the calling of the right LibAConv size function for
  # the type of "arg". %>
<%  syscall.args.each do |arg| %>
    req_size += <%=aconv_size(arg, "my_arch", "server_arch")%>;
<%  end %>
  }
  req = calloc(1, req_size);
  if(req == NULL)
    return NULL;
<%# Another hack added to support the special system calls %>
<%  if @@special_syscall[syscall.rsc]
      # I get the values given the "syscall.rsc" key. For each value,
      # I save the macro string into "str".
      @@special_syscall[syscall.rsc].each_with_index do |c, i| 
        str = "#ifdef #{c}"
        str = "#elif defined #{c}" if i != 0 %>
<%# I print the string  %>
<%=str%> 
  /* The system call is not defined in this architecture, so I return NULL */
  return NULL;
<%    end %>
#else
<%  end # end of "if @@special_syscall[syscall.rsc]" %> 

/* I get the __RSC_* constant */
<%# If it's a network system call the "sys?" methods returns true because a SYS_* constant is defined %>
<%  if syscall.sys? %>
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_<%=syscall.name%>, <%= syscall.sys? ? syscall.sys : NO_VALUE %>, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(__NR_socketcall, <%= syscall.sys? ? syscall.sys : NO_VALUE %>, my_arch)) == __RSC_ERROR ) {
#endif
<%# The array "@@x86_64_without64" is defined into the "common_code.rb" file. If syscall.nr is contained into that
  # list I need to remove the trailing "64" before print the constant. %>
<%  elsif @@x86_64_without64.include?(syscall.nr) %>
#ifdef __x86_64__
	if( (rsc_const = nr2rsc(__NR_<%=syscall.name.sub(/64/, '')%>, <%= syscall.sys? ? syscall.sys : NO_VALUE %>, my_arch)) == __RSC_ERROR ) {
#else
	if( (rsc_const = nr2rsc(<%= syscall.sys? ? "__NR_socketcall" : "__NR_#{syscall.name}"%>, <%= syscall.sys? ? syscall.sys : NO_VALUE %>, my_arch)) == __RSC_ERROR ) {
#endif

<%  else %>
	if( (rsc_const = nr2rsc(<%= syscall.sys? ? "__NR_socketcall" : "__NR_#{syscall.name}"%>, <%= syscall.sys? ? syscall.sys : NO_VALUE %>, my_arch)) == __RSC_ERROR ) {
<%  end %>
    free(req);
	  return NULL;
  }
<%# I print the closing #endif %>
<% if @@special_syscall[syscall.rsc] %>
#endif
<%  end %>
  req->req_type = RSC_SYS_REQ;
  req->req_rsc_const = htons(rsc_const);
  req->req_size = req_size;

<%  if(syscall.has_read_args?) 
      # For each read pointer argument "arg" I initialize two variables used some rows below.
      syscall.read_args.each do |arg| 
        # I save the size variable name defined before into "size_arg_name" argument.
        size_arg_name = arg.is_size_a_var? ? "#{arg.size_var.name}_value" :  "#{arg.name}_size_value"
        # If save the size value of the pointer into "size_arg_value".
        if(arg.is_size_a_var? && arg.size_var.type.pointer?)
          size_arg_value = "*#{arg.size_var.name}"
        else
          size_arg_value = aconv_size(arg, "my_arch", "server_arch", true)
        end
%>
  /* I manage the case in which the read pointer is NULL*/
  <%# I use the "name" method on "arg" to get the name of the argument.
    # I use the previously defined "size_arg_name" and "size_arg_value" to initialize
    # the size variables %>
  if(<%=arg.name%> == NULL)
    <%=size_arg_name%> = 0;
  else
    <%=size_arg_name%> = <%=size_arg_value%>;
<%    end 
    end %>
<%# I create a list of all the size variable. To do so I select only the read arguments
  # and I generate the variable names %>
<%  size_list = syscall.args.select{|arg| arg.read?}.collect do |arg| 
                                                      if(arg.is_size_a_var?)
                                                        "#{arg.size_var.name}_value"
                                                      else
                                                        "#{arg.name}_size_value"
                                                      end 
                                                     end
%>

<%# If the list isn't empty, I print it. To do so I append a '+' sign after each element 
  # using the "join" method %>
<% if not size_list.empty? %>
  req->req_size += <%="#{size_list.join(' + ')}"%>;
<%  end   %>
  /* I transform 'req_size' in network byte order and I save 
   * the system call arguments into the request.
   * If the two architectures are different, the LibAConv functions are called*/
  req->req_size = htonl(req->req_size);
  if(my_arch == server_arch) {
<%# I iterate over all the arguments to generate the assignment code %>
<%  syscall.args.each do |arg| 
      # If "arg" is an array, I generate the assignment code for each item
      if arg.type.array? %>
    if(<%=arg.name%> != NULL) {
<%      arg.type.array_size.times do |i| %>
      (req-><%=arg.name%>)[<%=i%>] = <%=arg.name%>[<%=i%>];
<%      end %>
    }
<%    else %>
    req-><%=arg.name%> = <%=arg.name%>; 
<%    end
	  end
%>
  } else {
    void *mem = (void *)req + sizeof(struct sys_req_header);
<%# I define some new variables %>
<%  syscall.args.each do |arg| 
      # If the argument IS a "size variable" and it's not a pointer, I save
      # into "parg" the argument for which it is the "size variable".
      if (arg.is_a_size_var? and not arg.type.pointer?)
        parg = arg.pointer_arg
        # If "parg" is a pointer and it's type is different from "void *" or "char *",
        # I define the new C variable
        if(parg.type.pointer? and (parg.type.type !~ /void \*/ and parg.type.type !~ /char \*/)) %>
    <%=arg.type%> <%=arg.name%>_new = <%=arg.name%>;
<%      end
      end 
    end%>
<%# For each argument I call the LibAConv functions  %>
<%  syscall.args.each do |arg| 
      if arg.type.array? %>
    if(<%=arg.name%> != NULL) {
      <%=aconv(arg, "my_arch", "server_arch", "mem")%>;
    }
<%    else %>
<%      if (arg.is_a_size_var? and not arg.type.pointer?)
          parg = arg.pointer_arg
          if(parg.type.pointer? and (parg.type.type !~ /void \*/ and parg.type.type !~ /char \*/)) %>
    if(<%=arg.name%> < <%=aconv_size(parg, "my_arch", "server_arch", true)%>)
      <%=arg.name%>_new = <%=aconv_size(parg, "my_arch", "server_arch", true)%>;
    <%=aconv(arg, "my_arch", "server_arch", "mem", false, "", "_new")%>; mem += <%=aconv_size(arg, "my_arch", "server_arch")%>;
<%        else %>
    <%=aconv(arg, "my_arch", "server_arch", "mem", false)%>; mem += <%=aconv_size(arg, "my_arch", "server_arch")%>;
<%        end
        else %>
    <%=aconv(arg, "my_arch", "server_arch", "mem", false)%>; mem += <%=aconv_size(arg, "my_arch", "server_arch")%>;
    
<%      end
      end
	  end
%>
  }
<%# I calculate the value of the Vector Vount "vcount", used to allocate
  # the right memory area for the iovec structure. If there aren't read pointer
  # "vcount" is equal to 1 because there is only the request header, otherwise I
  # have to add the number of read pointers; to do so I select them from the argument
  # list and I get the size of the resulting array.%>
<%  if syscall.has_read_args?
      # the +1 is for the request structure  
      vcount = 1 + syscall.args.select{|arg| arg.read?}.length 
    else
      vcount = 1
    end%>
      
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
<%# Here I save the value of the Ruby "vcount" into the C "vcount" %>
  vcount = <%=vcount%>;
<%    syscall.read_args.each do |arg| %>
  if(<%=arg.name%> == NULL)
    vcount--;
<%    end %>

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = req;
  v[0].iov_len = req_size;
  *total_size = v[0].iov_len;
<%# I assign to the iovec elements the read pointers %>
<%  if syscall.has_read_args? %>
  i = 1;
<%  end%>
<%    syscall.read_args.each_with_index do |arg, i|
        size_arg_name = arg.is_size_a_var? ? "#{arg.size_var.name}_value" :  "#{arg.name}_size_value" 
%> 
  if(<%=arg.name %> != NULL) {
    v[i].iov_len =  <%=size_arg_name%>;
    if(my_arch == server_arch) {
      v[i].iov_base = <%=arg.name%>;
    } else {
<%    if (arg.is_a_size_var? and arg.type.pointer?)
        parg = arg.pointer_arg
        if(parg.type.pointer? and (parg.type.type !~ /void \*/ and parg.type.type !~ /char \*/)) %>
      <%=arg.type.type.sub(/\*/, "")%> <%=arg.name%>_new = *<%=arg.name%>;
<%      end
      end %>

      v[i].iov_base = malloc(v[i].iov_len);
      if(v[i].iov_base == NULL)
        return NULL;
<%    if (arg.is_a_size_var? and arg.type.pointer?)
        parg = arg.pointer_arg
        if(parg.type.pointer? and (parg.type.type !~ /void \*/ and parg.type.type !~ /char \*/)) %>
      if(*<%=arg.name%> < <%=aconv_size(parg, "my_arch", "server_arch", true)%>)
        <%=arg.name%>_new = <%=aconv_size(parg, "my_arch", "server_arch", true)%>;
      <%= aconv(arg, "my_arch", "server_arch", "v[i].iov_base", true, "", "_new") %>;
<%      else %>
      <%= aconv(arg, "my_arch", "server_arch", "v[i].iov_base", true) %>;
<%      end
      else %>
      <%= aconv(arg, "my_arch", "server_arch", "v[i].iov_base", true) %>;
<%    end %>
    }
    *total_size += v[i].iov_len;
    <%# the following line prints a 'i++' if and only if the is not the last iteration %>
    <%= (i == (syscall.read_args.size - 1)) ? '' : 'i++;' %> 
  }
<%    end %> 
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct <%=syscall.name%>_req),
      rsc2str(ntohs(req->req_rsc_const)), ntohs(req->req_rsc_const), 
      ntohl(req->req_size), ntohl(req->req_size));
  <%# The "list_str" and "list_arg" contain, respectively, the formatted string to print and
    # the list of arguments. %>
  <% list_str = syscall.args.collect {|arg| "#{arg.name} = #{arg.type.printf_conv_spec} (0x%lX)"} 
    list_arg = syscall.args.collect {|arg| name = "req->#{arg.name}"; [name, name] }.flatten%>  
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: <%= list_str.join('; ') %>", <%= list_arg.join(', ')%>);

  return v;
}

<%# Here ends the iteration of over all the system calls supported by UMView to produce
  # the definitions of the rscc_create_<system call name>_request() functions %>
<% end %>

/*##########################################################*/
/*##                                                      ##*/
/*##  RESPONSE MANAGEMENT FUNCTIONS                       ##*/
/*##                                                      ##*/ 
/*##########################################################*/
<%# Here the iteration over the system calls supported by UMView starts again, to produce
  # the code for the rscc_manage_<system call name>_response() functions %>
<% nr_all.each_umview do |syscall| %>
struct iovec *rscc_manage_<%=syscall.name%>_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, <%= syscall.args.join(', ')%>) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);



  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_rsc_const = %s (0x%lX); resp_size = %d (0x%lX) bytes", 
      sizeof(struct sys_resp_header),
      rsc2str(resp_header->resp_rsc_const), resp_header->resp_rsc_const, 
      resp_header->resp_size, resp_header->resp_size);
  RSC_DEBUG(RSCD_MINIMAL, "\tretval = %d (0x%lX); errno = %d (0x%lX)\n", 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

<%# I insert the code to manage write arguments, if they exist %>
<%  if syscall.has_write_args?%>  
  /* I read the buffers */
  if(resp_header->resp_size > sizeof(struct sys_resp_header)) {
<%#There is more than 1 read argument %>
    int i;
    
    vcount = <%= syscall.write_args.size%>;
<%  syscall.write_args.each do |arg| %>
    if(<%=arg.name%> == NULL)
      vcount--;
<%  end %> 
    if(vcount != 0) {
	    v = calloc(vcount, sizeof(struct iovec));
	    if(v == NULL) {
	      fprintf(stderr, "Cannot allocate memory for vector v");
	      return NULL;
	    }
	
	    *nbytes = 0;
	    i = 0;
    <%  read_sizes = []
        # This iterator iterates over the write arguments and provides,
        # inside the block, of the index besides of the argument
        syscall.each_write_arg_with_index do |arg, j|
          # Here I control if the write pointer "arg" has the <retval> tag.
	        if(arg.size_retval?) 
	  %> 
	    if(<%=arg.name%> != NULL && resp_header->resp_retval > 0) {
	      v[i].iov_base = <%=arg.name%>;
	      v[i].iov_len =  resp_header->resp_retval;
	      *nbytes += resp_header->resp_retval;
	      <%= j == (syscall.args.select{|a| a.write?}.length - 1) ? "" : "i++;"%> 
	    }
	  <%    else%> 
      if(<%=arg.name%> != NULL) {
	      v[i].iov_base = <%=arg.name%>;
	      v[i].iov_len =  <%=arg.size%>;
	      *nbytes += <%=arg.size%>; 
	      <%= j == (syscall.args.select{|a| a.write?}.length - 1) ? "" : "i++;"%> 
      }
	  <%    end
	      end
	      read_sizes = syscall.args.select{|arg| arg.read?}.collect{|arg| arg.size}
	  %> 
    }
  }
<%  end %>


  *iovec_count = vcount;
  return v;
}

<% end %>


/*##########################################################*/
/*##                                                      ##*/
/*##  RSCC FUNCTIONS                                      ##*/
/*##                                                      ##*/
/*##########################################################*/
<%# Here the iteration over the system calls supported by UMView starts again, to produce
  # the code for the rscc_<system call name>() functions %>
<% nr_all.each_umview do |syscall| %>
int rscc_<%= syscall.name %>(<%= syscall.args.join(', ') %>) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  /* I build the request */
  v = rscc_create_<%= syscall.name %>_request(&nbytes, &iovec_count, <%= syscall.args.collect{|arg| arg.name}.join(', ') %>);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall '<%= syscall.name %>'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);

  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }

  /* I call the rscc_manage_<%=syscall.name%>_response(). If the return value isn't NULL,
   * I need to read other data (the write buffers). The returned value is a list of struct iovec, 
   * one for each write buffer. The ->iov_base of each element points to the syscall argument,
   * in this way the data are read directly into the original buffer. After the call of the
   * management functions the fields into the resp_header are un-marshaled and ready to be used. */
  v = rscc_manage_<%=syscall.name%>_response(&resp_header, &iovec_count, &nbytes, <%=syscall.args.collect{|a| a.name}.join(', ')%>);
  if(v != NULL) {
    /* I read the buffers (if they aren't NULL)...*/
	  nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
	  if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
<% end %>

# if 0
int rsc_recvmsg(int s, struct msghdr *msg, int flags) {
  struct recvmsg_req recvmsg_req;
  struct recvmsg_resp recvmsg_resp;
  int nwrite, nread, i, total_size;
  size_t *iov_len_array;
  enum rsc_constant rsc_const;


  memset(&recvmsg_req, 0, sizeof(struct recvmsg_req));
  if( (rsc_const = nr2rsc(__NR_socketcall, SYS_RECVMSG, my_arch)) == __RSC_ERROR )
    return -1;
  recvmsg_req.req_rsc_const = htons(rsc_const);
  /* The size of the request is formed by:
   * 1. the size of structure recvmsg_req
   * 2. the size of the msg->msg_name and msg->msg_controll buffers 
   * 3. the sizes of iov_base buffers inside the msg->msg_iov array */
  total_size = sizeof(struct recvmsg_req);
  if(msg->msg_name != NULL)
    total_size += msg->msg_namelen;

  if(msg->msg_control != NULL)
    total_size += msg->msg_controllen;
  
  if(msg->msg_iov != NULL)
    total_size += msg->msg_iovlen * sizeof(size_t);

  recvmsg_req.req_size = htonl(total_size);
  recvmsg_req.s = s;
  memcpy(&(recvmsg_req.msg), msg, sizeof(recvmsg_req.msg));
  recvmsg_req.flags = flags;

  printf("RECVMSG: Header: req_rsc_const = %d (%lX); req_size = %d (%lX)\n", ntohl(recvmsg_req.req_rsc_const), ntohl(recvmsg_req.req_rsc_const), ntohl(recvmsg_req.req_size), ntohl(recvmsg_req.req_size));
  printf("s = %d, flags = %d\n", recvmsg_req.s, recvmsg_req.flags);
  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, msg);

  /* I send the request header */
  nwrite = write_n_bytes(rsc_sockfd, &recvmsg_req, sizeof(struct recvmsg_req));
  if(nwrite != sizeof(struct recvmsg_req)) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, sizeof(struct recvmsg_req));
    return -1;
  }

  /* Now I have to send the data pointed by the pointer inside the msg structure: */
  /* 1. "msg_name": it can be null, so I send it only if it isn't null. */
  if(msg->msg_name != NULL) {
    printf("Sending msg_name (len = %d)\n", msg->msg_namelen);
    nwrite = write_n_bytes(rsc_sockfd, msg->msg_name, msg->msg_namelen);
    printf("Sent %d/%d bytes\n", nwrite, msg->msg_namelen);
    if(nwrite != msg->msg_namelen) {
      fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_namelen);
      return -1;
    }
  }
  
  /* 2. "msg_iov": it's an array of buffers so I don't need to send them, but I have
   *               to send the length of each buffer. */
  if(msg->msg_iov != NULL) {
    iov_len_array = calloc(msg->msg_iovlen, sizeof(size_t));
    for(i = 0; i < msg->msg_iovlen; i++) {
      printf("msg->msg_iov[%d].iov_len = %d\n", i, (msg->msg_iov[i]).iov_len);
      iov_len_array[i] = (msg->msg_iov[i]).iov_len;
    }
  }

  printf("msg->msg_iovlen = %d\n", msg->msg_iovlen);
  for(i = 0; i < msg->msg_iovlen; i++) { printf("iov_len_array[%d] = %d\n", i, iov_len_array[i]); }

  nwrite = write_n_bytes(rsc_sockfd, iov_len_array, msg->msg_iovlen * sizeof(size_t));
  printf("Sent %d/%d byte od msg->msg_iov\n", nwrite, msg->msg_iovlen);
  if(nwrite != msg->msg_iovlen * sizeof(size_t)) {
    fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_iovlen);
    return -1;
  }

  /* 3. "msg_control" */
  if(msg->msg_control != NULL) {
    printf("Sending msg_control (len = %d)\n", msg->msg_controllen);
    nwrite = write_n_bytes(rsc_sockfd, msg->msg_control, msg->msg_controllen);
    printf("Sent %d/%d byte od msg->msg_control\n", nwrite, msg->msg_controllen);
    if(nwrite != msg->msg_controllen) {
      fprintf(stderr, "I've sent only %d/%d bytes of msg->msg_name.\n", nwrite, msg->msg_controllen);
      return -1;
    }
  }
  
  nread = read_n_bytes(rsc_sockfd, &recvmsg_resp, sizeof(struct recvmsg_resp));
  if(nread != sizeof(struct recvmsg_resp)) {
    fprintf(stderr, "I've read only %d/%d bytes.\n", nwrite, sizeof(struct recvmsg_req));
    return -1;
  }
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s", rsc2str(recvmsg_resp.resp_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", recvmsg_resp.resp_type, recvmsg_resp.resp_type, recvmsg_resp.resp_size, recvmsg_resp.resp_size, recvmsg_resp.resp_retval, recvmsg_resp.resp_retval, recvmsg_resp.resp_errno, recvmsg_resp.resp_errno);

  if(recvmsg_resp.resp_retval != -1) {
    int i;
    for(i = 0; i < msg->msg_iovlen; i++) {
      nread = read_n_bytes(rsc_sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
      printf("Reading into buffer # %d; read %d bytes; buffer size = %d bytes\n", i, nread, msg->msg_iov[i].iov_len);
    }
  }
  
  printf("############## => recvmsg_resp.msg_controllen = %d\n", recvmsg_resp.msg_controllen);
  msg->msg_controllen = recvmsg_resp.msg_controllen;
  if(recvmsg_resp.msg_controllen != 0)
    nread = read_n_bytes(rsc_sockfd, msg->msg_control, recvmsg_resp.msg_controllen);
  else
    msg->msg_control = NULL;

  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, msg);
  errno = recvmsg_resp.resp_errno;
  return recvmsg_resp.resp_retval;
}
#endif

/* This function build the request for the system call 'ioctl' */
struct iovec *rscc_create_ioctl_request(int *total_size, int *iovec_count, u_int32_t size_type, int d, int request, void *arg) {
  struct ioctl_req *ioctl_req;
  enum rsc_constant rsc_const;
  int i;
  struct iovec *v;
  size_t vcount;
  int arg_size_value;

  ioctl_req = calloc(1, sizeof(struct ioctl_req));
  if(ioctl_req == NULL)
    return NULL;
	if( (rsc_const = nr2rsc(__NR_ioctl, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(ioctl_req);
	  return NULL;
  }
  ioctl_req->req_type = RSC_SYS_REQ;
  ioctl_req->req_rsc_const = htons(rsc_const);

  /* If arg is NULL or is a write pointer, don't send it */
  if(arg != NULL && (size_type & IOCTL_R))
    arg_size_value = size_type & IOCTL_LENMASK;
  else
    arg_size_value = 0;


  ioctl_req->req_size = htonl(sizeof(struct ioctl_req) + arg_size_value);

	ioctl_req->d = d;
  ioctl_req->request = request;
  ioctl_req->arg = arg;        
  /* There are pointers to buffers used by the system call to read data, so
   * I've to send them. */
  vcount = 1;
  if(arg != NULL && (size_type & IOCTL_R))
    vcount++;

  v = calloc(vcount, sizeof(struct iovec));
  if(v == NULL) {
    fprintf(stderr, "Cannot allocate memory for vector v");
    return NULL;
  }

  v[0].iov_base = ioctl_req;
  v[0].iov_len = sizeof(struct ioctl_req);
  *total_size = v[0].iov_len;
  i = 1;
 
  if(arg != NULL && (size_type & IOCTL_R)) {
    v[i].iov_base = arg;
    v[i].iov_len =  arg_size_value;
    *total_size += v[i].iov_len;
  }
  *iovec_count = vcount;

  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(ioctl_req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct ioctl_req),
      rsc2str(ntohs(ioctl_req->req_rsc_const)), ntohs(ioctl_req->req_rsc_const), 
      ntohl(ioctl_req->req_size), ntohl(ioctl_req->req_size));
    
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: d = %ld (0x%lX); request = %ld (0x%lX); arg = %p (0x%lX)", 
      ioctl_req->d, ioctl_req->d, ioctl_req->request, ioctl_req->request, ioctl_req->arg, ioctl_req->arg);

  return v;
}

struct iovec *rscc_manage_ioctl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int32_t size_type, void *arg) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  int byte_num = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);

  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_rsc_const = %d (0x%lX); resp_retval = %d (0x%lX); errno = %d (0x%lX)\n", 
      sizeof(struct sys_resp_header),
      resp_header->resp_type, resp_header->resp_type,
      resp_header->resp_size, resp_header->resp_size, 
      resp_header->resp_rsc_const, resp_header->resp_rsc_const, 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  if((resp_header->resp_size > sizeof(struct sys_resp_header)) && 
      (arg != NULL) && (size_type & IOCTL_W)) {
    v = calloc(1, sizeof(struct iovec));
	  if(v == NULL) {
	    fprintf(stderr, "Cannot allocate memory for vector v");
	    return NULL;
	  }
    v[0].iov_base = arg;
    v[0].iov_len = size_type & IOCTL_LENMASK;
    vcount = 1;
    byte_num = v[0].iov_len;
  }
  *nbytes = byte_num;
  *iovec_count = vcount;
  return v;
}

int rscc_ioctl(int d, int request, void *arg) {
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  u_int32_t size_type;

  /* I get the type and the size of 'arg' */
  size_type = rscc_check_ioctl_request(request);
  /* An error occurs or the 'request' isn't managed */
  if(size_type == 0 || size_type == IOCTL_UNMANAGED)
    return -1;


  /* I build the request */
  v = rscc_create_ioctl_request(&nbytes, &iovec_count, size_type, d, request, arg);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'ioctl'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);
  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }
  
  /* I read the additional data, if there is. */
  v = rscc_manage_ioctl_response(&resp_header, &iovec_count, &nbytes, size_type, arg);
  if(v != NULL) {
    nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
    if(nread != nbytes) {
      fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
      return -1;
    }
  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}

/***********************************************************************************************/
/***********************************************************************************************/
/***********************************************************************************************/

#ifndef RSCDEBUG
static 
#endif
struct ioctl_cache *ioctl_cache_init(int size) {
  struct ioctl_cache *cache;
  cache = calloc(1, sizeof(struct ioctl_cache));
  if(cache == NULL)
    return NULL;
  cache->size = size;
  cache->nentry = 0;

  return cache;
}

#ifndef RSCDEBUG
static 
#endif
void ioctl_cache_add(struct ioctl_cache *cache, int request, u_int32_t size_type) {
  struct ioctl_cache_el *el;
  el = calloc(1, sizeof(struct ioctl_cache_el));
  assert(el != NULL);
  /* I fill the request and update the pointers */
  el->request    = request;
  el->size_type  = size_type;
  /* There isn't room, I have to pop the last element,
   * before push it the new one */
  if(cache->nentry == cache->size) {
    cache->last = cache->last->prev;
    free(cache->last->next);
    cache->last->next = NULL;
    cache->nentry -= 1;
  } else if(cache->nentry == 0) 
    cache->last = el;
  el->next = cache->first;
  if(cache->first != NULL)
    cache->first->prev = el;
  cache->first = el;
  cache->nentry += 1;
}


#ifndef RSCDEBUG
static 
#endif
u_int32_t ioctl_cache_search(struct ioctl_cache *cache, int request) {
  struct ioctl_cache_el *el;
  for(el = cache->first; el != NULL; el = el->next) {
    if(el->request == request)
      return el->size_type;
  }

  return 0;
}

/* Returns the size_type for the given request. The returned values
 * can be:
 * - 0: if an error occurs
 * - IOCTL_UNMANAGED: if the server doesn't manage 'request'
 * - otherwise is the size_type value */
u_int32_t rscc_check_ioctl_request(int request) {
  struct ioctl_req_header req;
  struct ioctl_resp_header resp;
  int ret;
  u_int32_t size_type;

  /* I control if the request is in the cache */
  size_type = ioctl_cache_search(ioctl_cache, request);
  if(size_type == 0) {
	  /* otherwise I call the server */
	  bzero(&req, sizeof(struct ioctl_req_header));
	  req.req_type = RSC_IOCTL_REQ;
	  req.req_size = htonl(sizeof(struct ioctl_req_header));
	  req.req_ioctl_request = htonl(request);
	
	  /* I send the request */
	  ret = write_n_bytes(rsc_sockfd, &req, sizeof(struct ioctl_req_header));
	  if(ret != sizeof(struct ioctl_req_header))
	    return 0;
	
	  /* I wait the answer */
	  ret = read_n_bytes(rsc_sockfd, &resp, sizeof(struct ioctl_resp_header));
	  if(ret != sizeof(struct ioctl_resp_header))
	    return 0;
	  resp.resp_size = ntohl(resp.resp_size);
	  resp.resp_size_type = ntohl(resp.resp_size_type);
	  /* I add it to the cache */
	  ioctl_cache_add(ioctl_cache, request, resp.resp_size_type);

    size_type = resp.resp_size_type;
  }

  return size_type;
}

#ifndef RSCDEBUG
static 
#endif
u_int16_t fcntl_cmd_type(int cmd) {
  u_int16_t res = 0;
  switch(cmd) {
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
      res = FCNTL_NO_3RD_ARG;
      break;
    case F_DUPFD:
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
    case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY:
      res = FCNTL_3RD_LONG;
      break;
    case F_SETLK:
    case F_SETLKW:
      res = FCNTL_3RD_FLOCK_R;
      break;
    case F_GETLK:
      res = FCNTL_3RD_FLOCK_RW;
      break;
    default:
      res = 0;
      break;
  }

  return res;
}

/* This function build the request for the system call 'fcntl' */
struct iovec *rscc_create_fcntl_request(int *total_size, int *iovec_count, u_int16_t cmd_type, int fd, int cmd, long third_arg) {
  struct fcntl_req *fcntl_req;
  enum rsc_constant rsc_const;
  struct iovec *v;
  size_t vcount;
  int third_arg_size;
  

  fcntl_req = calloc(1, sizeof(struct fcntl_req));
  if(fcntl_req == NULL)
    return NULL;
	if( (rsc_const = nr2rsc(__NR_fcntl, NO_VALUE, my_arch)) == __RSC_ERROR ) {
    free(fcntl_req);
	  return NULL;
  }
  fcntl_req->req_type = RSC_SYS_REQ;
  fcntl_req->req_rsc_const = htons(rsc_const);

	fcntl_req->fd = fd;
  fcntl_req->cmd = cmd;
	fcntl_req->cmd_type = cmd_type;
  /* If there is a third argument, I manage it */
  if(cmd_type == FCNTL_NO_3RD_ARG) {
    fcntl_req->req_size = htonl(sizeof(struct fcntl_req));
  
    *iovec_count = 1;
    v = calloc(*iovec_count, sizeof(struct iovec));
    if(v == NULL) {
      fprintf(stderr, "Cannot allocate memory for vector v");
      return NULL;
    }
    v[0].iov_base = fcntl_req;
    v[0].iov_len = sizeof(struct fcntl_req);
    *total_size = v[0].iov_len;
  } else {
    /* I set the request fields accordingly with the
     * type of the third argument */
    if(cmd_type == FCNTL_3RD_LONG) {
      third_arg_size = 0;
      fcntl_req->third.arg = third_arg;
      vcount = 1;
    } else {
      struct flock *lock = (struct flock *)third_arg;
      vcount = 1;
      third_arg_size = 0;
      if(lock != NULL && (cmd_type == FCNTL_3RD_FLOCK_R || cmd_type == FCNTL_3RD_FLOCK_RW)) {
        third_arg_size = sizeof(struct flock);
        vcount = 2;
      }
      fcntl_req->third.lock = lock;
    }
  
    fcntl_req->req_size = htonl(sizeof(struct fcntl_req) + third_arg_size);

    /* There are pointers to buffers used by the system call to read data, so
     * I've to send them. */
    v = calloc(vcount, sizeof(struct iovec));
    if(v == NULL) {
      fprintf(stderr, "Cannot allocate memory for vector v");
      return NULL;
    }

    v[0].iov_base = fcntl_req;
    v[0].iov_len = sizeof(struct fcntl_req);
    *total_size = v[0].iov_len;
 
    /* If vcount == 2, the third argument is a non-NULL pointer
     * to a struct flock. */
    if(vcount == 2) {
      v[1].iov_base = fcntl_req->third.lock;
      v[1].iov_len =  sizeof(struct flock);
      *total_size += v[1].iov_len;
    }
    *iovec_count = vcount;
  } 

	rsc_const = nr2rsc(__NR_fcntl, NO_VALUE, my_arch);
  RSC_DEBUG(RSCD_MINIMAL, "==> REQUEST %s:", rsc2str(ntohs(fcntl_req->req_rsc_const)));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): req_rsc_const = %s (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(struct fcntl_req),
      rsc2str(ntohs(fcntl_req->req_rsc_const)), ntohs(fcntl_req->req_rsc_const), 
      ntohl(fcntl_req->req_size), ntohl(fcntl_req->req_size));
  RSC_DEBUG(RSCD_MINIMAL, "\tArguments: fd = %ld (0x%lX); cmd = %ld (0x%lX);", fcntl_req->fd, fcntl_req->fd, fcntl_req->cmd, fcntl_req->cmd);
  
  return v;
 
}

struct iovec *rscc_manage_fcntl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int16_t cmd_type, long third_arg) {
  struct iovec *v = NULL;
  size_t vcount = 0;
  int bytes_num = 0;
  resp_header->resp_rsc_const = ntohs(resp_header->resp_rsc_const);
  resp_header->resp_size = ntohl(resp_header->resp_size);
  resp_header->resp_retval = ntohl(resp_header->resp_retval); 
  resp_header->resp_errno = ntohl(resp_header->resp_errno);

  RSC_DEBUG(RSCD_MINIMAL, "<== RESPONSE %s:", rsc2str(resp_header->resp_rsc_const));
  RSC_DEBUG(RSCD_MINIMAL, "\tHeader(%dB): resp_type = %d (0x%lX); resp_size = %d (0x%lX) bytes; resp_rsc_const = %d (0x%lX); resp_retval = %d (0x%lX); errno = %d (0x%lX)\n", 
      sizeof(struct sys_resp_header),
      resp_header->resp_type, resp_header->resp_type,
      resp_header->resp_size, resp_header->resp_size, 
      resp_header->resp_rsc_const, resp_header->resp_rsc_const, 
      resp_header->resp_retval, resp_header->resp_retval, 
      resp_header->resp_errno, resp_header->resp_errno);

  
  /* If the third argument is a write pointer to a struct flock and the 
   * size of the response is greater than the size of a normal response,
   * read the flock structure */
  if( ((cmd_type == FCNTL_3RD_FLOCK_W) || (cmd_type == FCNTL_3RD_FLOCK_RW)) &&
      (resp_header->resp_size > sizeof(struct sys_resp_header)) ) {
            /* I read the 'lock' argument (id it's not NULL) */
      struct flock *lock = (struct flock *)third_arg;
      if( lock != NULL) {
        v = calloc(1, sizeof(struct iovec));
        if(v == NULL) {
	        fprintf(stderr, "Cannot allocate memory for vector v");
          return NULL;
        }
        v[0].iov_base = lock;
        v[0].iov_len = sizeof(struct flock);
        vcount = 1;
        bytes_num = v[0].iov_len;
      }
  }
  *iovec_count = vcount;
  *nbytes = bytes_num;
  return v;
}

int rscc_fcntl(int fd, int cmd, ...) {
  va_list ap;
  struct sys_resp_header resp_header;
  int nwrite, nread;
  int nbytes;
  struct iovec *v;
  int iovec_count;
  long third_arg = 0;
  u_int16_t cmd_type;
  /* I get some info about 'cmd' */
  if((cmd_type = fcntl_cmd_type(cmd)) == 0)
    return -1;
  /* If there is a third argument, I read it */
  if(cmd_type != FCNTL_NO_3RD_ARG) {
    va_start(ap, cmd);
    third_arg = va_arg(ap, long);
    va_end(ap);
  }

  /* I build the request */
  v = rscc_create_fcntl_request(&nbytes, &iovec_count, cmd_type, fd, cmd, third_arg);
  if(v == NULL) {
    fprintf(stderr, "I cannot create the request for the syscall 'fcntl'.\n");
    return -1;
  }
    
  /* I send the request ...*/
  nwrite = writev_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
  if(nwrite != nbytes) {
    fprintf(stderr, "I've sent only %d/%d bytes.\n", nwrite, nbytes);
    /* I free the request and the iovec structure */
    free(v[0].iov_base); free(v);
    return -1;
  }
  free(v[0].iov_base); free(v);
  /* ... and I wait the answer */
  nread = read_n_bytes(rsc_sockfd, &resp_header, sizeof(struct sys_resp_header));
  if(nread != sizeof(struct sys_resp_header)) {
    fprintf(stderr, "I've ent only %d/%d bytes.\n", nread, sizeof(struct sys_resp_header));
    return -1;
  }
  /* I read the additional data, if there is. */
  v = rscc_manage_fcntl_response(&resp_header, &iovec_count, &nbytes, cmd_type, third_arg);
  if(v != NULL) {
    nread = readv_n_bytes(rsc_sockfd, v, iovec_count, nbytes);
    if(nread != nbytes) {
	    fprintf(stderr, "I've read only %d/%d bytes.\n", nread, nbytes);
	    free(v);
	    return -1;
	  }

  }

  errno = resp_header.resp_errno;
  return resp_header.resp_retval;
}
