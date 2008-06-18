/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   event_sub_common.c: client and server common code for event subscription management
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
#include "rsc_messages.h"
int rsc_es_msg_size(u_int8_t type) {
  int size;
  switch(type) {
    case EVENT_SUB_REQ:
      size = sizeof(struct rsc_es_req); break;
    case EVENT_SUB_ACK:
      size = sizeof(struct rsc_es_ack); break;
    case EVENT_SUB_RESP:
      size = sizeof(struct rsc_es_resp); break;
    case EVENT_SUB_DEREG:
      size = sizeof(struct rsc_es_dereg); break;
    default:
      size = -1; break;
  }

  return size;
}
