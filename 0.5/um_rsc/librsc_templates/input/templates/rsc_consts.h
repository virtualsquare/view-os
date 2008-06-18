<%#
     This is part of RSC file generator program
  
     rsc_consts.c: template file for __RSC_* constants definition and 
                   management functions
     
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
<% @@filename = "rsc_consts.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: __RSC_* constants definition and management functions
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
#ifndef __RSC_CONSTS_HEADER__
#define __RSC_CONSTS_HEADER__
#include <stdlib.h>
#include "aconv.h"

/* A struct nr_and_sys that doesn't contain a .sys value has the .sys 
 * field equal to "NO_VALUE".
 * A empty struct nr_and_sys has the .nr field equal to "NO_VALUE",
 * the .sys field could have any value.
 */
#define NO_VALUE	(-1)
struct nr_and_sys {
	int32_t nr;
	int32_t sys;
};

/*########################################################################*/
/*##  __RSC_* CONSTANTS                                                 ##*/
/*########################################################################*/
enum rsc_constant {
	__RSC_ERROR = -1, /* Used when there isn't a valid __RSC_ constant */
	__RSC_FIRST = 0,
<% nr_all.each_with_index { |const, i| 
   if( i == 0 )%>
  <%= "#{const.rsc} = __RSC_FIRST,\n" %>
<%   else %>
  <%= "#{const.rsc},\n" %>
<%   end
 }%>
	__RSC_LAST = <%= nr_all.last.rsc %>

};

/*  From __RSC_* to __NR_* constants and vice versa                        */
struct nr_and_sys *rsc2nr(enum rsc_constant rsc_const, enum arch arch);
enum rsc_constant nr2rsc(int32_t nr_const, int32_t sys, enum arch arch);

/*########################################################################*/
/*##  CONSTANTS to STRINGS                                              ##*/
/*########################################################################*/

/* Strings returned when is required a string for a __RSC_* or __NR_*
 * constant that doesn't exist.
 */
extern char *rsc_not_existing;
extern char *nr_not_existing;
extern char *rsc_to_str[];

/*  The following tables are used to convert to string a __NR_* or
 *  __RSC_* constant.        
 */

#define X86_TO_STR_SIZE <%= nr_x86.max.nr_num + 1 %> 

extern char * x86_to_str[];

#define X86_64_TO_STR_SIZE <%= nr_x86_64.max.nr_num + 1 %> 

extern char * x86_64_to_str[];

#define PPC_TO_STR_SIZE <%= nr_ppc.max.nr_num + 1 %> 

extern char * ppc_to_str[];

/* SYS_ values are equal in each architecture, so a single table is
 * sufficient.
 */
#define SYS_TO_STR_SIZE 18
extern char *sys_to_str[];

#endif /* __RSC_CONSTANT_HEADER__ */
