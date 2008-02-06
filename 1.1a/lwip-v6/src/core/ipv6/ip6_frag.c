/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2005 Diego Billi University of Bologna - Italy
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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */
/* @file
 * 
 * This is the IP packet segmentation and reassembly implementation.
 *
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
 * Author: Jani Monoses <jani@iv.ro> 
 * original reassembly code by Adam Dunkels <adam@sics.se>
 * 
 */

#include "lwip/opt.h"

#if IPv6_FRAGMENTATION || IPv4_FRAGMENTATION

#include "lwip/debug.h"

#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_frag.h"

/*---------------------------------------------------------------------------*/

//#ifndef IP_REASS_DEBUG
//#define IP_REASS_DEBUG   DBG_OFF
//#endif

/* FIX: used only for printf warning */
#ifdef IP_REASS_DEBUG
#define  UINT  (unsigned int)
#endif

/*---------------------------------------------------------------------------*/

/*
 * Copy len bytes from offset in pbuf to buffer 
 *
 * helper used by both ip_reass and ip_frag
 */
INLINE static struct pbuf *
copy_from_pbuf(struct pbuf *p, u16_t * offset, u8_t * buffer, u16_t len)
{
	u16_t l;

	p->payload = (u8_t *) p->payload + *offset;
	p->len -= *offset;
  	while (len) {
		l = len < p->len ? len : p->len;
		memcpy(buffer, p->payload, l);
		buffer += l;
		len -= l;
		if (len)
			p = p->next;
		else
			*offset = l;
	}
	return p;
}

/*---------------------------------------------------------------------------*/
/* Macro and costants */
/*---------------------------------------------------------------------------*/

static const u8_t bitmap_bits[8] = { 0xff, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };


/* IPv4 reassembly timer timeout */
#define IP_REASS_TIMER_TIMEOUT  1000

/* Max IP Payload len */
#define IP_REASS_BUFSIZE         65535

/* Expire time of a fragmented packet */
#define IP4_REASS_MAX_AGE         5

#define IP4_REASS_FLAG_USED       0x40
#define IP4_REASS_FLAG_LASTFRAG   0x01

/* Reassembly buffer */
struct ip_reassbuf {
	u8_t  ipv;     /* ip version (4, 6).  0 if the entry is empty */
	u32_t id;      /* fragmentation id (16bit Ipv4, 32bit Ipv6) */

	u8_t  age;     /* seconds */
	u8_t  flags;   /* entry's state */
	u32_t len;

	u8_t  buf[IP_REASS_BUFSIZE]; 

#define IP4_REASS_BITMAP_SIZE  (IP_REASS_BUFSIZE / (8 * 8))
	u8_t  bitmap[IP4_REASS_BITMAP_SIZE];
};

#define CLEAR_ENTRY(e) \
	do { \
		(e)->ipv = 0; \
		(e)->id    = 0; \
		(e)->age = 0; \
		(e)->flags = 0; \
		(e)->len = 0; \
		bzero((e)->bitmap, IP4_REASS_BITMAP_SIZE);  \
	} while (0)

#define fill_bitmap(bit, off, len) \
	do { \
		int ___i; \
		bit[(off)/(8*8)] |= bitmap_bits[((off)/8)&7]; \
		for (___i = 1 + (off)/(8*8); ___i < ((off)+(len))/(8*8); ++___i) \
			bit[___i] = 0xff; \
		bit[((off)+(len))/(8*8)] |= ~bitmap_bits[(((off)+(len))/8)&7]; \
	} while (0); 


/* Number of fragmented packets we can reassembly */
#define IP_REASS_POOL_SIZE     5
static struct ip_reassbuf ip_reassembly_pool[IP_REASS_POOL_SIZE];


/* Costants for fragmentation buffers */
#define MAX_MTU 1500

/* Reassembly timer */
INLINE static void 
ip_reass_tmr(void *arg)
{
	int i;

	for (i=0; i < IP_REASS_POOL_SIZE; i++) {
		/* If this entry is used increment entry age */
		if (ip_reassembly_pool[i].flags & IP4_REASS_FLAG_USED) {
		    ip_reassembly_pool[i].age++;
			/* This entry is too old */
			if (ip_reassembly_pool[i].age >= IP4_REASS_MAX_AGE) {
				CLEAR_ENTRY(& ip_reassembly_pool[i] );
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass_tmr: free entry %d (IPv%d, id=%u)\n", i, ip_reassembly_pool[i].ipv, UINT ip_reassembly_pool[i].id));
			}
		}
	}

	sys_timeout(IP_REASS_TIMER_TIMEOUT, ip_reass_tmr, NULL);
}

#if 0
#define IP_REASS_EXPIRE_TIMEOUT  5000

static void ip_reass_expire_tm(void *arg)
{
	struct ip_reassbuf * entry = (struct ip_reassbuf *) arg;

	CLEAR_ENTRY( entry );

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: free entry (IPv%d, id=%u)\n", entry->ipv, UINT entry->id));
}
#endif


/*---------------------------------------------------------------------------*/
/* Module functions */
/*---------------------------------------------------------------------------*/

/* Initialize IPv4 Reassembly cache */
void 
ip_frag_reass_init(void)
{
	/* FIX: rough init, change it? */
	bzero(ip_reassembly_pool, IP_REASS_POOL_SIZE * sizeof(struct ip_reassbuf));

#if IPv4_FRAGMENTATION
	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: IPv4 fragmentation enabled.\n", __func__));
#endif
#if IPv6_FRAGMENTATION
	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: IPv6 fragmentation enabled.\n", __func__));
#endif

	sys_timeout(IP_REASS_TIMER_TIMEOUT, (sys_timeout_handler) ip_reass_tmr, NULL);
}


/*---------------------------------------------------------------------------*/
/* IPv4 */
/*---------------------------------------------------------------------------*/

#if IPv4_FRAGMENTATION

struct pbuf *ip4_reass(struct pbuf *p)
{
	struct pbuf *q;
	struct ip4_hdr *fragment_hdr, *entry_iphdr;
	u32_t offset, len;
	u16_t i;
	u16_t pos;

	IPFRAG_STATS_INC(ip_frag.recv);
	LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: start\n"));

	fragment_hdr = (struct ip4_hdr *) p->payload;

	/* Search in the pool for matching fragments */
	for (pos=0; pos < IP_REASS_POOL_SIZE; pos++) {
		/* Lookup for IPv4 entries, If this entry is used check it */
		if (ip_reassembly_pool[pos].ipv == 4)
		if (ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_USED) {
		    entry_iphdr   = (struct ip4_hdr *) ip_reassembly_pool[pos].buf;
			/* cached fragment matches receivd fragment? */
			if (ip_reassembly_pool[pos].id == IPH4_ID(fragment_hdr) &&
				ip4_addr_cmp(&entry_iphdr->src, &fragment_hdr->src) && 
				ip4_addr_cmp(&entry_iphdr->dest, &fragment_hdr->dest)
				) 
				break;
		}
	}

	/* No match found. Try Create new one. */
	if (pos >= IP_REASS_POOL_SIZE) {
		/* Search empty entry for this new fragment */
		for (pos=0; pos < IP_REASS_POOL_SIZE; pos++) 
			/* This entry is empty. Let's use it */
			if (ip_reassembly_pool[pos].ipv == 0)
			if (!(ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_USED)) {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: new packet (pos=%d)\n", pos));

				/* Reset entry data */
				ip_reassembly_pool[pos].flags = IP4_REASS_FLAG_USED;

				ip_reassembly_pool[pos].age   = 0;
#if 0
				sys_timeout(IP_REASS_EXPIRE_TIMEOUT, ip_reass_expire_tm, &ip_reassembly_pool[pos]);
#endif

				ip_reassembly_pool[pos].ipv   = 4;
				ip_reassembly_pool[pos].id    = IPH4_ID(fragment_hdr);
				ip_reassembly_pool[pos].len   = IP4_HLEN;

				/* Clean bitmap */
				bzero(ip_reassembly_pool[pos].bitmap, IP4_REASS_BITMAP_SIZE);

				/* Save fragment in the entry */
				entry_iphdr   = (struct ip4_hdr *) ip_reassembly_pool[pos].buf;
				memcpy(entry_iphdr, fragment_hdr, IP4_HLEN);

				/* update bitmap */
				fill_bitmap(ip_reassembly_pool[pos].bitmap, 0, IP4_HLEN); 
				break;
			}
	}

	/* Entry found */
	if (pos < IP_REASS_POOL_SIZE) {

		entry_iphdr   = (struct ip4_hdr *) ip_reassembly_pool[pos].buf;

		LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: matching old packet (pos=%d)\n", pos));
		IPFRAG_STATS_INC(ip_frag.cachehit);

		/* Find out the offset in the reassembly buffer where we should
		   copy the fragment. */
		len    = ntohs(IPH4_LEN(fragment_hdr)) - IPH4_HL(fragment_hdr) * 4;
		offset = IP4_HLEN + (ntohs(IPH4_OFFSET(fragment_hdr)) & IP_OFFMASK) * 8;

		/* If the offset or the offset + fragment length overflows the
		   reassembly buffer, we discard the entire packet. */
		if (offset > IP_REASS_BUFSIZE || offset + len > IP_REASS_BUFSIZE) {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: fragment outside of buffer (%d:%d/%d).\n", UINT offset, UINT (offset + len), UINT IP_REASS_BUFSIZE));
			/* Make this entry empty */
			CLEAR_ENTRY( & ip_reassembly_pool[pos] );
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: remove entry %d.\n", pos));
			goto nullreturn;
		}

		/* Copy the fragment into the reassembly buffer, at the right offset. */
		LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: copying with offset %d into %d:%d\n", UINT offset, UINT (IP4_HLEN + offset), UINT (IP4_HLEN + offset + len)));
		i = IPH4_HL(fragment_hdr) * 4;

		copy_from_pbuf(p, &i, &ip_reassembly_pool[pos].buf[offset], len);

		/* Update the bitmap. */
		if (offset / (8 * 8) == (offset + len) / (8 * 8)) {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: updating single byte in bitmap.\n"));
			/* If the two endpoints are in the same byte, we only update that byte. */
			ip_reassembly_pool[pos].bitmap[offset / (8 * 8)] |= bitmap_bits[(offset / 8) & 7] & ~bitmap_bits[((offset + len) / 8) & 7];
		}
		else {
			/* If the two endpoints are in different bytes, we update the
			   bytes in the endpoints and fill the stuff inbetween with
			   0xff. */
			fill_bitmap(ip_reassembly_pool[pos].bitmap, offset, len);
		}

		/* If this fragment has the More Fragments flag set to zero, we
		   know that this is the last fragment, so we can calculate the
		   size of the entire packet. We also set the
		   IP_REASS_FLAG_LASTFRAG flag to indicate that we have received
		   the final fragment. */
		if ((ntohs(IPH4_OFFSET(fragment_hdr)) & IP_MF) == 0) {
			ip_reassembly_pool[pos].flags |= IP4_REASS_FLAG_LASTFRAG;
			ip_reassembly_pool[pos].len    = offset + len;
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: last fragment seen, total len %d\n", UINT ip_reassembly_pool[pos].len));
		}

		/* Finally, we check if we have a full packet in the buffer. We do
		   this by checking if we have the last fragment and if all bits
		   in the bitmap are set. */
		if (ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_LASTFRAG) {

			/* Check all bytes up to and including all but the last byte in the bitmap. */
			for (i = 0; i < ip_reassembly_pool[pos].len / (8 * 8) - 1; ++i) {
				if (ip_reassembly_pool[pos].bitmap[i] != 0xff) {
					LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: last fragment seen, bitmap %d/%d failed (%x)\n", i, UINT ip_reassembly_pool[pos].len / (8 * 8) - 1, UINT ip_reassembly_pool[pos].bitmap[i]));
					goto nullreturn;
				}
			}

			/* Check the last byte in the bitmap. It should contain just the
			   right amount of bits. */
			if (ip_reassembly_pool[pos].bitmap[ip_reassembly_pool[pos].len / (8 * 8)] != (u8_t) ~ bitmap_bits[ip_reassembly_pool[pos].len / 8 & 7]) {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: last fragment seen, bitmap %d didn't contain %x (%x)\n", UINT ip_reassembly_pool[pos].len / (8 * 8), UINT ~bitmap_bits[ip_reassembly_pool[pos].len / 8 & 7], UINT ip_reassembly_pool[pos].bitmap[ip_reassembly_pool[pos].len / (8 * 8)]));
				goto nullreturn;
			}

			/* Pretend to be a "normal" (i.e., not fragmented) IP packet from now on. */
			IPH4_LEN_SET(entry_iphdr, htons(ip_reassembly_pool[pos].len));
			IPH4_OFFSET_SET(entry_iphdr, 0);
			IPH4_CHKSUM_SET(entry_iphdr, 0);
			IPH4_CHKSUM_SET(entry_iphdr, inet_chksum(entry_iphdr, IP4_HLEN));

			/* If we have come this far, we have a full packet in the
			   buffer, so we allocate a pbuf and copy the packet into it. We
			   also reset the timer. */

			pbuf_free(p);

			p = pbuf_alloc(PBUF_LINK, ip_reassembly_pool[pos].len, PBUF_POOL);
			if (p != NULL) {
				i = 0;
				for (q = p; q != NULL; q = q->next) {
					/* Copy enough bytes to fill this pbuf in the chain. The
					   available data in the pbuf is given by the q->len
					   variable. */
					LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: memcpy from %p (%d) to %p, %ld bytes\n", 
						(void *) &ip_reassembly_pool[pos].buf[i], i, 
						q->payload, q->len > (ip_reassembly_pool[pos].len - i) ? ip_reassembly_pool[pos].len - i : q->len));

					memcpy(q->payload, &ip_reassembly_pool[pos].buf[i], q->len > ip_reassembly_pool[pos].len - i ? ip_reassembly_pool[pos].len - i : q->len);
					i += q->len;
				}
				IPFRAG_STATS_INC(ip_frag.fw);
			}
			else {
				IPFRAG_STATS_INC(ip_frag.memerr);
			}

			CLEAR_ENTRY( & ip_reassembly_pool[pos] );

			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip_reass: p %p\n", (void *) p));
			return p;
		}
	}

nullreturn:
	IPFRAG_STATS_INC(ip_frag.drop);
	pbuf_free(p);
	return NULL;
}



/**
 * Fragment an IP packet if too large
 *
 * Chop the packet in mtu sized chunks and send them in order
 * by using a fixed size static memory buffer (PBUF_ROM)
 */
err_t 
ip4_frag(struct pbuf *p, struct netif *netif, struct ip_addr *dest)
{
	u8_t buf[MAX_MTU];

	struct pbuf *rambuf;
	struct pbuf *header;
	struct ip4_hdr *iphdr;
	u16_t nfb = 0;
	u16_t left, cop;
	u16_t mtu;
	u16_t ofo, omf;
	u16_t last;
	u16_t poff = IP4_HLEN;
	u16_t tmp;

	mtu = netif->mtu;

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: start\n", __func__));

	/* Get a RAM based MTU sized pbuf */
	rambuf = pbuf_alloc(PBUF_LINK, 0, PBUF_REF);
	rambuf->tot_len = rambuf->len = mtu;
	rambuf->payload = MEM_ALIGN((void *) buf);

	/* Copy the IP header in it */
	iphdr = rambuf->payload;
	memcpy(iphdr, p->payload, IP4_HLEN);

	/* Save original offset */
	tmp = ntohs(IPH4_OFFSET(iphdr));
	ofo = tmp & IP_OFFMASK;
	omf = tmp & IP_MF;

	left = p->tot_len - IP4_HLEN;

	while (left) {
		last = (left <= mtu - IP4_HLEN);

		/* Set new offset and MF flag */
		ofo += nfb;
		tmp = omf | (IP_OFFMASK & (ofo));
		if (!last)
			tmp = tmp | IP_MF;
		IPH4_OFFSET_SET(iphdr, htons(tmp));

		/* Fill this fragment */
		nfb = (mtu - IP4_HLEN) / 8;
		cop = last ? left : nfb * 8;

		p = copy_from_pbuf(p, &poff, (u8_t *) iphdr + IP4_HLEN, cop);

		/* Correct header */
		IPH4_LEN_SET(iphdr, htons(cop + IP4_HLEN));
		IPH4_CHKSUM_SET(iphdr, 0);
		IPH4_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP4_HLEN));

		if (last)
			pbuf_realloc(rambuf, left + IP4_HLEN);
		/* This part is ugly: we alloc a RAM based pbuf for 
		 * the link level header for each chunk and then 
		 * free it.A PBUF_ROM style pbuf for which pbuf_header
		 * worked would make things simpler.
		 */
		header = pbuf_alloc(PBUF_LINK, 0, PBUF_RAM);
		pbuf_chain(header, rambuf);

		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: netif->output\n", __func__));
		netif->output(netif, header, dest);
		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: netif->output finish\n", __func__));

		IPFRAG_STATS_INC(ip_frag.xmit);
		pbuf_free(header);
		left -= cop;
	}
	pbuf_free(rambuf);
	return ERR_OK;
}

#endif


/*---------------------------------------------------------------------------*/
/* IPv6 */
/*---------------------------------------------------------------------------*/

#if IPv6_FRAGMENTATION

struct pbuf *
ip6_reass(struct pbuf *p, struct ip6_fraghdr *fragext, struct ip_exthdr *lastext)
{
	struct pbuf *q;
	struct ip_hdr      *entry_iphdr;
	struct ip_hdr      *fragment_hdr;
	u32_t offset, len;
	u16_t i;
	u16_t pos;

	u16_t unfragpart_len; /* length of unfragmentable part */

	IPFRAG_STATS_INC(ip_frag.recv);
	LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: start\n"));
	LWIP_DEBUGF(IP_REASS_DEBUG, ("Next  : %d\n", UINT IP6_NEXTHDR(fragext) ));
	LWIP_DEBUGF(IP_REASS_DEBUG, ("ID    : %d\n", UINT IP6_ID(fragext)      ));
	LWIP_DEBUGF(IP_REASS_DEBUG, ("Offset: %d\n", UINT IP6_OFFSET(fragext)  ));
	LWIP_DEBUGF(IP_REASS_DEBUG, ("M     : %d\n", UINT IP6_M(fragext)       ));

	fragment_hdr = (struct ip_hdr *) p->payload;

	/* Search in the pool for matching fragments */
	for (pos=0; pos < IP_REASS_POOL_SIZE; pos++) {
		/* If this entry is used */
		if (ip_reassembly_pool[pos].ipv == 6)
		if (ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_USED) {

		    entry_iphdr   = (struct ip_hdr *) ip_reassembly_pool[pos].buf;

			/* cached fragment matches receivd fragment? */
			if (ip_reassembly_pool[pos].id == IP6_ID(fragext) &&
				ip_addr_cmp(&entry_iphdr->src , &fragment_hdr->src ) && 
				ip_addr_cmp(&entry_iphdr->dest, &fragment_hdr->dest)
				) 
				break;
		}
	}

	/* No match found. Try Create new one. */
	if (pos >= IP_REASS_POOL_SIZE) {
		/* Search empty entry for this new fragment */
		for (pos=0; pos < IP_REASS_POOL_SIZE; pos++) 
			if (ip_reassembly_pool[pos].ipv == 0)
			/* This entry is empty. Let's use it */
			if (!(ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_USED)) {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: new packet (pos=%d)\n", pos));

				/* Reset entry data */
				ip_reassembly_pool[pos].ipv    = 6;
				ip_reassembly_pool[pos].id     = IP6_ID(fragext);
				ip_reassembly_pool[pos].age    = 0;
				ip_reassembly_pool[pos].flags  = IP4_REASS_FLAG_USED;

				ip_reassembly_pool[pos].len    = unfragpart_len;

				/* Clean bitmap */
				bzero(ip_reassembly_pool[pos].bitmap, IP4_REASS_BITMAP_SIZE);

				/* Save fragment in the entry */
				entry_iphdr   = (struct ip_hdr *) ip_reassembly_pool[pos].buf;

				/* Copy the whole  Unfragmentable Part */
				unfragpart_len = ((int)fragext) - ((int)fragment_hdr);
				memcpy(entry_iphdr, fragment_hdr, unfragpart_len);


				fill_bitmap(ip_reassembly_pool[pos].bitmap, 0, unfragpart_len); 
				break;
			}
	}

	/* Entry found */
	if (pos < IP_REASS_POOL_SIZE) {

		unfragpart_len = ((int)fragext) - ((int)fragment_hdr);

		entry_iphdr   = (struct ip_hdr *) ip_reassembly_pool[pos].buf;

		LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: matching old packet (pos=%d)\n", pos));
		IPFRAG_STATS_INC(ip_frag.cachehit);

		/* Find out the offset in the reassembly buffer where we should
		   copy the fragment. */
		/* Payload Length of the IPv6 header contains the length of this fragment 
           packet only (excluding the length of the IPv6 header itself) */
		len    = ntohs(IPH_PAYLOADLEN(fragment_hdr)) + IP_HLEN - unfragpart_len - sizeof(struct ip6_fraghdr);  
		offset = unfragpart_len + IP6_OFFSET(fragext);

		LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: Len = %d.\n", UINT len));

		/* If the offset or the offset + fragment length overflows the
		   reassembly buffer, we discard the entire packet. */
		if (offset > IP_REASS_BUFSIZE || offset + len > IP_REASS_BUFSIZE) {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: fragment outside of buffer (%d:%d/%d).\n", UINT offset, UINT (offset + len), UINT IP_REASS_BUFSIZE));
			/* Make this entry empty */
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: remove entry %d.\n", pos));
			CLEAR_ENTRY( & ip_reassembly_pool[pos] );
			goto nullreturn;
		}

		/* Copy the fragment into the reassembly buffer, at the right offset. */
		LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: copying with offset %d into %d:%d\n",UINT offset,  UINT (unfragpart_len + offset),  UINT (unfragpart_len + offset + len)));
		i = unfragpart_len + sizeof(struct ip6_fraghdr);
		copy_from_pbuf(p, &i, &ip_reassembly_pool[pos].buf[offset], len);

		/* Update the bitmap. */
		if (offset / (8 * 8) == (offset + len) / (8 * 8)) {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: updating single byte in bitmap.\n"));
			/* If the two endpoints are in the same byte, we only update that byte. */
			ip_reassembly_pool[pos].bitmap[offset / (8 * 8)] |= bitmap_bits[(offset / 8) & 7] & ~bitmap_bits[((offset + len) / 8) & 7];
		}
		else {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip4_reass: updating many bytes in bitmap (%ld:%ld).\n", 1 + offset / (8 * 8), (offset + len) / (8 * 8)));
			/* If the two endpoints are in different bytes, we update the
			   bytes in the endpoints and fill the stuff inbetween with
			   0xff. */
			fill_bitmap(ip_reassembly_pool[pos].bitmap, offset, len);
		}

		/* If this fragment has the More Fragments flag set to zero, we
		   know that this is the last fragment, so we can calculate the
		   size of the entire packet. We also set the
		   IP_REASS_FLAG_LASTFRAG flag to indicate that we have received
		   the final fragment. */
		if (IP6_M(fragext) == 0) {
			ip_reassembly_pool[pos].flags |= IP4_REASS_FLAG_LASTFRAG;
			ip_reassembly_pool[pos].len    = offset + len;
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: last fragment seen, total len %d\n", UINT ip_reassembly_pool[pos].len));
		}
		else {
			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: NOT last fragment.\n"));
		}

		/* Finally, we check if we have a full packet in the buffer. We do
		   this by checking if we have the last fragment and if all bits
		   in the bitmap are set. */
		if (ip_reassembly_pool[pos].flags & IP4_REASS_FLAG_LASTFRAG) {

			/* Check all bytes up to and including all but the last byte in the bitmap. */
			for (i = 0; i < ip_reassembly_pool[pos].len / (8 * 8) - 1; ++i) {
				if (ip_reassembly_pool[pos].bitmap[i] != 0xff) {
					LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: last fragment seen, bitmap %d/%ld failed (%x)\n", i, ip_reassembly_pool[pos].len / (8 * 8) - 1, ip_reassembly_pool[pos].bitmap[i]));
					goto nullreturn;
				}
			}

			/* Check the last byte in the bitmap. It should contain just the
			   right amount of bits. */
			if (ip_reassembly_pool[pos].bitmap[ip_reassembly_pool[pos].len / (8 * 8)] != (u8_t) ~ bitmap_bits[ip_reassembly_pool[pos].len / 8 & 7]) {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: last fragment seen, bitmap %ld didn't contain %x (%x)\n", ip_reassembly_pool[pos].len / (8 * 8), ~bitmap_bits[ip_reassembly_pool[pos].len / 8 & 7], ip_reassembly_pool[pos].bitmap[ip_reassembly_pool[pos].len / (8 * 8)]));
				goto nullreturn;
			}

			/* Pretend to be a "normal" (i.e., not fragmented) IP packet from now on. */
			IPH_PAYLOADLEN_SET(entry_iphdr, ip_reassembly_pool[pos].len);

			//lastext = ip_last_exthdr_before_fraghdr(p);
			if (lastext != NULL) {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: memcpy from %p (%d) to %p, %ld bytes\n", (void *) &ip_reassembly_pool[pos].buf[i], i, q->payload, q->len > ip_reassembly_pool[pos].len - i ? ip_reassembly_pool[pos].len - i : q->len));
				/* FIX FIX FIX */
			} 
			else {
				LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: no extension headers before fragment\n"));
            	/* No extension header. Modify NextHdr field in IPv6 Header */
				IPH_NEXTHDR_SET(entry_iphdr, fragext->nexthdr);
			}

			/* If we have come this far, we have a full packet in the
			   buffer, so we allocate a pbuf and copy the packet into it. We
			   also reset the timer. */
			pbuf_free(p);

			p = pbuf_alloc(PBUF_LINK, ip_reassembly_pool[pos].len, PBUF_POOL);
			if (p != NULL) {
				i = 0;
				for (q = p; q != NULL; q = q->next) {
					/* Copy enough bytes to fill this pbuf in the chain. The
					   available data in the pbuf is given by the q->len
					   variable. */
					LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: memcpy from %p (%d) to %p, %ld bytes\n", (void *) &ip_reassembly_pool[pos].buf[i], i, q->payload, q->len > ip_reassembly_pool[pos].len - i ? ip_reassembly_pool[pos].len - i : q->len));
					memcpy(q->payload, &ip_reassembly_pool[pos].buf[i], q->len > ip_reassembly_pool[pos].len - i ? ip_reassembly_pool[pos].len - i : q->len);
					i += q->len;
				}
				IPFRAG_STATS_INC(ip_frag.fw);
			}
			else {
				IPFRAG_STATS_INC(ip_frag.memerr);
			}

			CLEAR_ENTRY( & ip_reassembly_pool[pos] );

			LWIP_DEBUGF(IP_REASS_DEBUG, ("ip6_reass: p %p\n", (void *) p));
			return p;
		}
	}
nullreturn:
	IPFRAG_STATS_INC(ip_frag.drop);
	pbuf_free(p);
	return NULL;
}



/**
 * Fragment an IP packet if too large
 *
 * Chop the packet in mtu sized chunks and send them in order
 * by using a fixed size static memory buffer (PBUF_ROM)
 */
err_t 
ip6_frag(struct pbuf *p, struct netif *netif, struct ip_addr *dest)
{
	u8_t buf6[MAX_MTU];

	struct pbuf *rambuf;
	struct pbuf *linkheader;

	struct ip_hdr       *iphdr;
	struct ip6_fraghdr  *fraghdr;

	u16_t mtu;
	u8_t  last;        /* last fragment, yes=1, no=0 */
	u16_t left;
	u16_t frag_maxlen; /* Len of fragment payload to create */
	u16_t offset;      /* offset of current frag */
	u16_t poffset;     /* used for copy_from_pbuf() */
	u16_t offset_m;    /* offset + M bit field value */
	u16_t ncopy;

	u16_t  unfragpart_len;  /* len of the Unfragmentable part */
	u8_t   nexthdr;         
	u16_t  destext_num;
	struct ip_exthdr  *exthdr, *last_exthdr;


	iphdr = (struct ip_hdr *) p->payload;

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: start\n", __func__));


	mtu = netif->mtu;


	/* Calculate len of Ipv6 Unfragmentable part */
	unfragpart_len = IP_HLEN;
	nexthdr = IPH_NEXTHDR(iphdr);

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: search next header %d\n", __func__, nexthdr));

	exthdr = NULL;
	destext_num = 0; /* Destination header can occour two times. We include the first */
	do {
		last_exthdr = exthdr;
		exthdr = (struct ip_exthdr *)  ((char*)p->payload + unfragpart_len);

		if (nexthdr == IP6_NEXTHDR_HOP) {
			nexthdr = exthdr->nexthdr;
		}
		else if (nexthdr == IP6_NEXTHDR_DEST && destext_num < 1) {
			nexthdr = exthdr->nexthdr;

			destext_num++;
		}
		else if (nexthdr == IP6_NEXTHDR_ROUTING) {        
			nexthdr = exthdr->nexthdr;
		}
		else {
        	break;
		}
	} while (1);

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: next header = %d\n", __func__, nexthdr));
	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: unfrag part len = %d\n", __func__, unfragpart_len));

	/* The Fragmentable Part of the original packet is divided into
	 * fragments, each, except possibly the last ("rightmost") one, 
	 * being an integer multiple of 8 octets long. 
	 */
	frag_maxlen =  ((mtu - unfragpart_len - IP_EXTFRAG_LEN) >> 3) << 3;

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: frag maxlen = %d\n", __func__, frag_maxlen));

	/* Get a RAM based sized pbuf for Unfragmentable part + Frag hdr*/
	rambuf = pbuf_alloc(PBUF_LINK, 0, PBUF_REF);
	rambuf->tot_len = rambuf->len = unfragpart_len + IP_EXTFRAG_LEN + frag_maxlen;
	rambuf->payload = MEM_ALIGN((void *) buf6);

	/* Copy Unfragmentable part (IP hdr + Ext hdrs) */
	iphdr = rambuf->payload;
	memcpy(iphdr, p->payload, unfragpart_len);

	/* Set NextHeader field in the IP header or the last Extension header */
	if (last_exthdr == NULL)
		IPH_NEXTHDR_SET(iphdr, IP6_NEXTHDR_FRAGMENT);
	else
		last_exthdr->nexthdr = IP6_NEXTHDR_FRAGMENT;

	/* Fill Frag header's fields common to all fragments */
	fraghdr = (struct ip6_fraghdr *) (((char *)iphdr) + unfragpart_len);
	fraghdr->nexthdr = nexthdr;
	fraghdr->id      = htonl(ip_id++);

	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: id = %d\n", __func__, UINT fraghdr->id));

	/* Create fragments */
	offset  = 0;
	poffset = unfragpart_len;
	left    = p->tot_len - unfragpart_len;
	LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: left = %d\n", __func__, left));
	while (left) {

		last = (left <= frag_maxlen) ? 1 : 0;

		/* Set offset and M bit*/
		offset_m = (offset>>3)<<3 ;
		if (!last)
			offset_m |= IP6_MF;
		fraghdr->offset_res_m = htons(offset_m);

		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: offset = %d\n", __func__, offset));

		/* Fill this fragment*/
		ncopy = last ? left : frag_maxlen;

		/* Payload Length of the original IPv6 header changed to contain
		   the length of this fragment packet only (excluding the length
		 * of the IPv6 header itself), */
		IPH_PAYLOADLEN_SET(iphdr, (unfragpart_len - IP_HLEN) + IP_EXTFRAG_LEN + ncopy);


		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: offset = %d (%4x) (last=%d) copy=%d\n", __func__, offset, offset_m, last, ncopy));

		p = copy_from_pbuf(p, &poffset, 
			((u8_t *) iphdr) + unfragpart_len + IP_EXTFRAG_LEN, ncopy);

		if (last)
			pbuf_realloc(rambuf, unfragpart_len + IP_EXTFRAG_LEN + left);

		/* This part is ugly: we alloc a RAM based pbuf for 
		 * the link level header for each chunk and then 
		 * free it.A PBUF_ROM style pbuf for which pbuf_header
		 * worked would make things simpler.
		 */
		linkheader = pbuf_alloc(PBUF_LINK, 0, PBUF_RAM);
		pbuf_chain(linkheader, rambuf);

		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: netif->output (pbuf len/tot=%d/%d)\n", __func__, linkheader->len, linkheader->tot_len ));
		netif->output(netif, linkheader, dest);
		LWIP_DEBUGF(IP_REASS_DEBUG, ("%s: netif->output finish\n", __func__));

		IPFRAG_STATS_INC(ip_frag.xmit);
		pbuf_free(linkheader);

		left   -= ncopy;
		offset += ncopy;
	}

	pbuf_free(rambuf);
	return ERR_OK;
}

#endif

#endif /* IPv6_FRAGMENTATION || IPv4_FRAGMENTATION */
