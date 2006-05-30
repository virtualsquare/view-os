/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */   
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */


/* inet6.c
 *
 * Functions common to all TCP/IP modules, such as the Internet checksum and the
 * byte order functions.
 *
 */


#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/inet.h"



/* chksum:
 *
 * Sums up all 16 bit words in a memory portion. Also includes any odd byte.
 * This function is used by the other checksum functions.
 *
 * For now, this is not optimized. Must be optimized for the particular processor
 * arcitecture on which it is to run. Preferebly coded in assembler.
 */

static u32_t
chksum(void *dataptr, u16_t len)
{
  u16_t *sdataptr = dataptr;
  u32_t acc;
  
  
  for(acc = 0; len > 1; len -= 2) {
    acc += *sdataptr++;
  }

  /* add up any odd byte */
  if (len == 1) {
    acc += htons((u16_t)((*(u8_t *)sdataptr) &0xff) << 8);
  }

  return acc;

}

/* inet_chksum_pseudo:
 *
 * Calculates the pseudo Internet checksum used by TCP and UDP for a pbuf chain.
 */

u16_t
inet6_chksum_pseudo(struct pbuf *p,
       struct ip_addr *src, struct ip_addr *dest,
       u8_t proto, u32_t proto_len)
{
  u32_t acc;
  struct pbuf *q;
  u8_t swapped, i;

  //ip_addr_debug_print(IP_DEBUG, src);

  //ip_addr_debug_print(IP_DEBUG, dest);

  //printf("proto %d proto_len %d\n",proto,proto_len);

  acc = 0;
  swapped = 0;
  for(q = p; q != NULL; q = q->next) {    
    acc += chksum(q->payload, q->len);
    while (acc >> 16) 
      acc = (acc & 0xffffUL) + (acc >> 16);
    if (q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
     }
  }

  if (swapped) {
    acc = ((acc & 0xff) << 8) | ((acc & 0xff00UL) >> 8);
  }
  
  for(i = ip_addr_is_v4comp(src)?6:0; i < 8; i++) {
    acc += ((u16_t *)src->addr)[i] & 0xffffUL;
    acc += ((u16_t *)dest->addr)[i] & 0xffffUL;
    while (acc >> 16) 
      acc = (acc & 0xffffUL) + (acc >> 16);
  }
  acc += (u16_t)htons((u16_t)proto);
  acc += htons(((u16_t *)&proto_len)[0]) & 0xffffUL;
  acc += htons(((u16_t *)&proto_len)[1]) & 0xffffUL;
  while (acc >> 16)
    acc = (acc & 0xffffUL) + (acc >> 16);
  return ~(acc & 0xffffUL);
}

/* inet_chksum:
 *
 * Calculates the Internet checksum over a portion of memory. Used primarely for IP
 * and ICMP.
 */

u16_t
inet_chksum(void *dataptr, u16_t len)
{
  u32_t acc, sum;

  acc = chksum(dataptr, len);
  sum = (acc & 0xffff) + (acc >> 16);
  sum += (sum >> 16);
  return ~(sum & 0xffff);
}

u16_t
inet_chksum_pbuf(struct pbuf *p)
{
  u32_t acc;
  struct pbuf *q;
  u8_t swapped;
  
  acc = 0;
  swapped = 0;
  for(q = p; q != NULL; q = q->next) {
    acc += chksum(q->payload, q->len);
    while (acc >> 16) {
      acc = (acc & 0xffff) + (acc >> 16);
    }    
    if (q->len % 2 != 0) {
      swapped = 1 - swapped;
      acc = (acc & 0xff << 8) | (acc & 0xff00 >> 8);
    }
  }
 
  if (swapped) {
    acc = ((acc & 0xff) << 8) | ((acc & 0xff00) >> 8);
  }
  return ~(acc & 0xffff);
}


/******************************************************************************/

/* FIX: review these */

#include "lwip/ip_addr.h"
#include "lwip/sockets.h"

#define INT16_SZ    2
#define IN4ADDR_SZ  4
#define IN6ADDR_SZ 16

static int
inet_pton4(const char *src, unsigned char *dst)
{
  static const char digits[] = "0123456789";
  unsigned char tmp[IN4ADDR_SZ], *tp;
  int saw_digit, octets, ch;

  saw_digit = 0;
  octets = 0;
  *(tp = tmp) = 0;
  while ((ch = *src++) != '\0') {
    const char *pch;

    if ((pch = strchr(digits, ch)) != NULL) {
      unsigned int new = *tp * 10 + (pch - digits);

      if (new > 255)
        return 0;
      *tp = new;
      if (! saw_digit) {
        if (++octets > 4)
          return 0;
        saw_digit = 1;
      }
    } else if (ch == '.' && saw_digit) {
      if (octets == 4)
        return 0;
      *++tp = 0;
      saw_digit = 0;
    } else
      return 0;
  }

  if (octets < 4)
    return 0;

  memcpy(dst, tmp, IN4ADDR_SZ);
  return 1;
}

static int
inet_pton6(const char *src, unsigned char *dst)
{
  static const char xdigits_l[] = "0123456789abcdef", xdigits_u[] = "0123456789ABCDEF";
  unsigned char tmp[IN6ADDR_SZ], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int ch, saw_xdigit;
  unsigned int val;
  
  tp = tmp;
  memset((tp = tmp), '\0', IN6ADDR_SZ);
  endp = tp + IN6ADDR_SZ;
  colonp = NULL;
  
  /* Leading :: requires some special handling. */
  if (*src == ':')
    if (*++src != ':')
      return 0;
  
  curtok = src;
  saw_xdigit = 0;
  val = 0;
  while ((ch = *src++) != '\0') {
    const char *pch;
  
    if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
      pch = strchr((xdigits = xdigits_u), ch);
    if (pch != NULL) {
      val <<= 4;
      val |= (pch - xdigits);  
      if  (val > 0xffff)
        return 0;
      saw_xdigit = 1;
      continue;
    }

    if (ch == ':') {
      curtok = src;
      if (!saw_xdigit) {
        if (colonp)
          return 0;
        colonp = tp;
        continue;
      }

      if (tp + INT16_SZ > endp)
        return 0;
      *tp++ = (unsigned char) (val >> 8) & 0xff;
      *tp++ = (unsigned char) val & 0xff;
      saw_xdigit = 0;
      val = 0;
      continue;
    }

    if (ch == '.' && ((tp + IN4ADDR_SZ) <= endp) && inet_pton4(curtok, tp) > 0) {
      tp += IN4ADDR_SZ;
      saw_xdigit = 0;
      break;	/* '\0' was seen by inet_pton4(). */
    }
    return 0;
  }

  if (saw_xdigit) {
    if (tp + INT16_SZ > endp)
      return 0;
    *tp++ = (unsigned char) (val >> 8) & 0xff;
    *tp++ = (unsigned char) val & 0xff;
  }

  if (colonp != NULL) {
    const int n = tp - colonp;
    int i;
  
    for (i = 1; i <= n; i++) {
      endp[- i] = colonp[n - i];
      colonp[n - i] = 0;
    }
    tp = endp;
  }

  if (tp != endp)
    return 0;
  
  memcpy(dst, tmp, IN6ADDR_SZ);
  
  return 1;
}

int
inet_ptonn(int af, const char *src, void *dst)
{
  int r;
  struct ip4_addr ip4;

  switch (af) {
    case AF_INET:

      r = inet_pton4(src, (void *)&ip4);
      if (r != 1)
        return r;

      IP64_CONV((struct ip_addr *) dst, &ip4);
      return r;

    case AF_INET6:
      return inet_pton6(src, dst);

    default:
#ifdef LWIP_PROVIDE_ERRNO
      errno = EAFNOSUPPORT;
#endif
      return -1;
  }
}

