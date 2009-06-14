/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   debiug.c: debug functions
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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "rsc_consts.h"
#include "debug.h"

#ifdef _PTHREAD_H
#include <pthread.h>
#endif

void rsc_debug(int level, int rscdebug_level, const char *file, const int line, const char *func, const char *fmt, ...) {
  va_list ap;
  if( rscdebug_level >= level ) {
    va_start(ap, fmt);
#ifdef _PTHREAD_H
		fprintf(stderr, "[%d:%lu] %s:%d %s(): ", getpid(), pthread_self(), file, line, func);
#else
		fprintf(stderr, "[%d] %s:%d %s(): ", getpid(), file, line, func);
#endif
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
		va_end(ap);

  }
}

/* type of print:
 * - 1: for ex
 * - 2: for char */
static void rsc_exdump_print_line(const void* text, int byte_num, int type) {
  int i;
  for(i = 0; i < byte_num; i++) {
    if((i != 0) && ((i % 4) == 0))
      fprintf(stderr, " ");
    switch (type) {
      case 2: {
        char c = (char)((char *)text)[i];
        /* I control if it's a printable char */
        if(c >= 32 && c <= 126) 
          fprintf(stderr, "%c", c);
        else
          fprintf(stderr, ".");
        break;
      }
      default:
        fprintf(stderr, "%02x", (unsigned char)((char *)text)[i]);
        break;
    }
  }
}

void rsc_exdump(int level, int rscdebug_level, const char *file, const int line, const char *func, const void* text, int len)
{
	int i;
	if ( rscdebug_level >= level)
	{
#ifdef _PTHREAD_H
		fprintf(stderr, "[%d:%lu] %s:%d %s(): [%d bytes]\n", getpid(), pthread_self(), file, line, func, len);
#else
		fprintf(stderr, "[%d] %s:%d %s(): [%d bytes]\n", getpid(), file, line, func, len);
#endif
    for (i = 0; i < len; i++) {
      if( (i == 0) || ((i % 16) == 0) ) {
        int bytes_num;
        if(i != 0) 
          fprintf(stderr, "\n");
        fprintf(stderr, "	%p:	", text + i);
        bytes_num = ((len - i) >= 16 ) ? 16 : (len - i);
        rsc_exdump_print_line(text + i, bytes_num, 1);
        if(bytes_num < 16) {
          int space_num, not_printed, j;
	        /* one space for each ex not printed (16 - len), each
	         * ex is 2 char long (* 2) and there is a space between
	         * 4 ex numbers */
	        not_printed = 16 - bytes_num;
	        space_num = not_printed * 2;
	        if(bytes_num < 4)
	          space_num += 3;
	        else if(bytes_num < 8)
	          space_num += 2;
	        else if(bytes_num < 12)
	          space_num += 1;

	        for(j = 0; j < space_num; j++)
            fprintf(stderr, " ");
	        fprintf(stderr, "\t");
        } else
          fprintf(stderr, "\t");
        rsc_exdump_print_line(text + i, bytes_num, 2);
      }
		}

		fprintf(stderr, "\n");
	}

}	

void rsc_print_msghdr(int level, struct msghdr *msg) {
  int i;

  RSC_DEBUG(level, "msg = {");
  RSC_DEBUG(level, "  msg_name = %p", msg->msg_name);
  RSC_DEBUG(level, "  msg_namelen = %d", msg->msg_namelen);
  RSC_DEBUG(level, "  msg_iov (%p) = {", msg->msg_iov);
  for(i = 0; i < msg->msg_iovlen; i++) {
    RSC_DEBUG(level, "    %d. iov_base = %p", i,(msg->msg_iov)[i].iov_base);
    RSC_DEBUG(level, "       iov_len = %d", (msg->msg_iov)[i].iov_len);
  }
  RSC_DEBUG(level, "  }");

  RSC_DEBUG(level, "  msg_iovlen = %d", msg->msg_iovlen);
  RSC_DEBUG(level, "  msg_control = %p", msg->msg_control);
  RSC_DEBUG(level, "  msg_controllen = %d", msg->msg_controllen);
  RSC_DEBUG(level, "  msg_flags = %d", msg->msg_flags);
  RSC_DEBUG(level, "}");
}
