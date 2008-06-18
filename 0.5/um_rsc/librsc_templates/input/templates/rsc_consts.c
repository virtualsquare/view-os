<%#
     This is part of RSC file generator program
  
     rsc_consts.c: template file for RSC constants management
     
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
<% @@filename = "rsc_consts.c" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: RSC constants management
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
#include <string.h>
#include "aconv.h"
#include "nr_to_rsc.h"
#include "rsc_to_nr.h"
#include "debug.h"

/*########################################################################*/
/*##                                                                    ##*/
/*##  LOCAL VARIABLES                                                   ##*/
/*##                                                                    ##*/
/*########################################################################*/

/* Strings returned when is required a string for a __RSC_* or __NR_*
 * constant that doesn't exist. */
char *rsc_not_existing = "__RSC_ CONSTANT DOESN'T EXIST!";
char *nr_not_existing = "__NR_ CONSTANT DOESN'T EXIST!";

/**************************************************************************/
/*  The following tables are used to convert to string a __NR_* or        */
/*  __RSC_* constant.                                                     */
/**************************************************************************/

<%= nr_all.table_rsc_to_str() %>

<%= nr_x86.table_nr_to_str %>

<%= nr_x86_64.table_nr_to_str %>

<%= nr_ppc.table_nr_to_str %>


/* SYS_ values are equal in each architecture,
 * so a single table is sufficent. */
char *sys_to_str[] = {
	/* 0. Isn't used */ "__NR_socketcall, UNDEFINED SYS_*",
	/* 1. SYS_SOCKET */ "__NR_socketcall, SYS_SOCKET",
	/* 2. SYS_BIND	*/ "__NR_socketcall, SYS_BIND",
	/* 3. SYS_CONNECT */ "__NR_socketcall, SYS_CONNECT",
	/* 4. SYS_LISTEN */ "__NR_socketcall, SYS_LISTEN",
	/* 5. SYS_ACCEPT */ "__NR_socketcall, SYS_ACCEPT",
	/* 6. SYS_GETSOCKNAME */ "__NR_socketcall, SYS_GETSOCKNAME",
	/* 7. SYS_GETPEERNAME */ "__NR_socketcall, SYS_GETPEERNAME",
	/* 8. SYS_SOCKETPAIR */ "__NR_socketcall, SYS_SOCKETPAIR",
	/* 9. SYS_SEND */ "__NR_socketcall, SYS_SEND",
	/* 10. SYS_RECV */ "__NR_socketcall, SYS_RECV",
	/* 11. SYS_SENDTO */ "__NR_socketcall, SYS_SENDTO",
	/* 12. SYS_RECVFROM */ "__NR_socketcall, SYS_RECVFROM",
	/* 13. SYS_SHUTDOWN */ "__NR_socketcall, SYS_SHUTDOWN",
	/* 14. SYS_SETSOCKOPT */ "__NR_socketcall, SYS_SETSOCKOPT",
	/* 15. SYS_GETSOCKOPT */ "__NR_socketcall, SYS_GETSOCKOPT",
	/* 16. SYS_SENDMSG */ "__NR_socketcall, SYS_SENDMSG",
	/* 17 SYS_RECVMSG */ "__NR_socketcall, SYS_RECVMSG"
};

/*########################################################################*/
/*##                                                                    ##*/
/*##  LOCAL FUNCTIONS                                                   ##*/
/*##                                                                    ##*/
/*########################################################################*/
static enum rsc_constant get_rsc(int32_t nr_const, int32_t sys, enum rsc_constant table[], int table_size) {
  enum rsc_constant res;

  if((nr_const < 0) || (nr_const >= table_size ))
    return __RSC_ERROR;

  res = table[nr_const];
  /* If "nr_const" is __NR_socketcall, then I have to get the right
   * __RSC_* constant using the SYS_* one. */
  if(res == __RSC_socketcall) {
    if( (sys != NO_VALUE) && (sys > 0) && (sys < SYS_TO_RSC_SIZE) )
      res = sys_to_rsc[sys];
    else
      /* I need the SYS_ value (and I need that is correct) if __NR_ is __NR_socketcall! */
      res = __RSC_ERROR;
  }

  return res;
}

static struct nr_and_sys *get_nr(enum rsc_constant rsc_const, struct nr_and_sys table[]) {
  struct nr_and_sys *res;
  if((rsc_const < __RSC_FIRST) || (rsc_const > __RSC_LAST))
    return NULL;

  res = &table[rsc_const];
  /* If the resulting structure is empty (both fields defined as NO_VALUE)
   * I return NUUL */
  if( (res->nr == NO_VALUE) && (res->sys == NO_VALUE) )
    res = NULL;
  return res;
}

static char *get_str(int32_t nr_const, int32_t sys, char *table[], int table_size) {
  char *res;

  if((nr_const < 0) || (nr_const >= table_size ))
    return nr_not_existing;
  res = table[nr_const];
  /* If "nr_const" is __NR_socketcall, then I have to get the right
   * __RSC_* constant using the SYS_* one. */
  if(strcmp("__NR_socketcall", res) == 0) {
    if( (sys != NO_VALUE) && (sys > 0) && (sys < SYS_TO_STR_SIZE) ) {
      res = sys_to_str[sys];
    } else {
      /* I need a correct SYS_ value __NR_ is __NR_socketcall! */
      res = nr_not_existing;
    }
  }

  return res;
}



/*########################################################################*/
/*##                                                                    ##*/
/*##  LIBRARY FUNCTIONS                                                 ##*/
/*##                                                                    ##*/
/*########################################################################*/
/* sys can be equal to NO_VALUE */
enum rsc_constant nr2rsc(int32_t nr_const, int32_t sys, enum arch arch) {
  enum rsc_constant res;
  
  switch(arch) {
    case ACONV_X86:
      res = get_rsc(nr_const, sys, x86_to_rsc, X86_TO_RSC_SIZE);
      break;
    case ACONV_PPC:
      res = get_rsc(nr_const, sys, ppc_to_rsc, PPC_TO_RSC_SIZE);
      break;
    case ACONV_X86_64:
      res = get_rsc(nr_const, sys, x86_64_to_rsc, X86_64_TO_RSC_SIZE);
      break;
    default:
      res = __RSC_ERROR;
      break;
  }

  RSC_DEBUG(RSCD_REQ_RESP, "nr2rsc: %s(# %d; sys = %d) => %s (# %d)", 
      nr2str(nr_const, sys, arch), nr_const, sys,
      res == __RSC_ERROR ? rsc_not_existing : rsc2str(res), res);
  return res ;
}

struct nr_and_sys *rsc2nr(enum rsc_constant rsc_const, enum arch arch) {
  struct nr_and_sys *res;
  switch(arch) {
    case ACONV_X86:
      res = get_nr(rsc_const, rsc_to_x86);
      break;
    case ACONV_PPC:
      res = get_nr(rsc_const, rsc_to_ppc);
      break;
    case ACONV_X86_64:
      res = get_nr(rsc_const, rsc_to_x86_64);
      break;
    default:
      res = NULL;
      break;
  }
  RSC_DEBUG(RSCD_REQ_RESP, "rsc2nr: %s(# %d) => %s (# %d; sys = %d)", 
      rsc2str(rsc_const), rsc_const, 
      res == NULL ? nr_not_existing : nr2str(res->nr, res->sys, arch), 
      res == NULL ? -1 : res->nr,
      res == NULL ? -1 : res->sys);
  return res;
}

char *rsc2str(enum rsc_constant rsc_const) {
  if((rsc_const < __RSC_FIRST) || (rsc_const > __RSC_LAST))
    return rsc_not_existing;

  return rsc_to_str[rsc_const];
}

char *nr2str(int32_t nr_const, int32_t sys, enum arch arch) {
  char *res;
  
  switch(arch) {
    case ACONV_X86:
      res = get_str(nr_const, sys, x86_to_str, X86_TO_STR_SIZE);
      break;
    case ACONV_PPC:
      res = get_str(nr_const, sys, ppc_to_str, PPC_TO_STR_SIZE);
      break;
    case ACONV_X86_64:
      res = get_str(nr_const, sys, x86_64_to_str, X86_64_TO_STR_SIZE);
      break;
    default:
      res = nr_not_existing;
      break;
  }

  return res;
}
