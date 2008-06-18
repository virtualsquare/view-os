/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   debug.h: debug header
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

#ifndef __DEBUG_HEADER__
#define __DEBUG_HEADER__
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "aconv.h"
#include "rsc_consts.h"

/* Debug levels */
#define RSCD_ERROR        0
#define RSCD_MINIMAL      1
#define RSCD_REQ_RESP     2
#define RSCD_MARSHALING   3
#define RSCD_EVENT_SUB    4
#define RSCD_RW           5

char *rsc2str(enum rsc_constant rsc_const);
char *nr2str(int32_t nr_const, int32_t sys, enum arch arch);

#ifdef RSCDEBUG
# ifndef RSC_DEBUG_LEVEL
#   error "RSC_DEBUG enabled but RSC_DEBUG_LEVEL undefined."
# endif
# define RSC_DEBUG(level, args...) rsc_debug(level, RSC_DEBUG_LEVEL, __FILE__, __LINE__, __func__, args)
# define RSC_EXDUMP(level, text, len) rsc_exdump(level, RSC_DEBUG_LEVEL, __FILE__, __LINE__, __func__, text, len)
# define RSC_PRINT_MSGHDR(level, msg)  rsc_print_msghdr(level, msg)

void rsc_debug(int level, int rscdebug_level, const char *file, const int line, const char *func, const char *fmt, ...);
void rsc_exdump(int level, int rscdebug_level, const char *file, const int line, const char *func, const void* text, int len);
void rsc_print_msghdr(int level, struct msghdr *msg);

#else
# define RSC_DEBUG(level, args...) 
# define RSC_EXDUMP(level, text, len)
# define RSC_PRINT_MSGHDR(level, msg)
#endif

#endif /* __DEBUG_HEADER__ */
