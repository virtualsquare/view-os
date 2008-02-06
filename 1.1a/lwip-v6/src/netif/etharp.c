/**
* @file
* Address Resolution Protocol module for IP over Ethernet
*
* Functionally, ARP is divided into two parts. The first maps an IP address
* to a physical address when sending a packet, and the second part answers
* requests from other machines for our physical address.
*
* This implementation complies with RFC 826 (Ethernet ARP). It supports
* Gratuitious ARP from RFC3220 (IP Mobility Support for IPv4) section 4.6
* if an interface calls etharp_query(our_netif, its_ip_addr, NULL) upon
* address change.
*/

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
*   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
*/   
/*
* Copyright (c) 2001-2003 Swedish Institute of Computer Science.
* Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
* Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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
*/

#include "lwip/opt.h"

#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/ip.h"
#include "lwip/stats.h"
#include "lwip/icmp.h"



/* ARP needs to inform DHCP of any ARP replies? */
#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
#include "lwip/dhcp.h"
#endif


/** the time an ARP entry stays valid after its last update,
* (240 * 5) seconds = 20 minutes.
*/
//#define ARP_MAXAGE 240
/** the time an ARP entry stays valid after its last update,
* (6 * 5) seconds = 0.5 minutes.
*/
#define ARP_MAXAGE 6
/** the time an ARP entry stays pending after first request,
 * (2 * 5) seconds = 10 seconds.
 * 
 * @internal Keep this number at least 2, otherwise it might
 * run out instantly if the timeout occurs directly after a request.
 */
#define ARP_MAXPENDING 2

#define HWTYPE_ETHERNET 1

/** ARP message types */
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define ARPH_HWLEN(hdr) (ntohs((hdr)->_hwlen_protolen) >> 8)
#define ARPH_PROTOLEN(hdr) (ntohs((hdr)->_hwlen_protolen) & 0xff)

#define ARPH_HWLEN_SET(hdr, len) (hdr)->_hwlen_protolen = htons(ARPH_PROTOLEN(hdr) | ((len) << 8))
#define ARPH_PROTOLEN_SET(hdr, len) (hdr)->_hwlen_protolen = htons((len) | (ARPH_HWLEN(hdr) << 8))

#define LINKOUTPUT(N,P) ({ \
			ETH_CHECK_PACKET_OUT((N),(P)); \
			(N)->linkoutput((N),(P)); \
			})
			
enum etharp_state {
  ETHARP_STATE_EMPTY=0,
  ETHARP_STATE_PENDING,
  ETHARP_STATE_STABLE,
  /** @internal transitional state used in etharp_tmr() for convenience*/
  ETHARP_STATE_EXPIRED
};

struct etharp_entry {
#if ARP_QUEUEING
  /** 
   * Pointer to queue of pending outgoing packets on this ARP entry.
   */
  struct pbuf *p;
#endif
  struct ip_addr ipaddr;
  struct eth_addr ethaddr;
  enum etharp_state state;
  u8_t ctime;
  u8_t if_id;
};

static const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}};
static struct etharp_entry arp_table[ARP_TABLE_SIZE];

#define ARP_INSERT_FLAG 1

/**
 * Try hard to create a new entry - we want the IP address to appear in
 * the cache (even if this means removing an active entry or so). */
#define ETHARP_TRY_HARD 1

static s8_t find_entry(struct ip_addr *ipaddr, u8_t flags);
static err_t update_arp_entry(struct netif *netif, struct ip_addr *ipaddr, struct eth_addr *ethaddr, u8_t flags);

/**
 * Initializes ARP module.
 */
void
etharp_init(void)
{
  /* global vars are zeroed by definition */
#if 0
  u8_t i;
  /* clear ARP entries */
  for(i = 0; i < ARP_TABLE_SIZE; ++i) {
    arp_table[i].state = ETHARP_STATE_EMPTY;
#if ARP_QUEUEING
    arp_table[i].p = NULL;
#endif
    arp_table[i].ctime = 0;
  }
#endif
}

/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ETHARP_TMR_INTERVAL microseconds (5 seconds),
 * in order to expire entries in the ARP table.
 */
void
etharp_tmr(struct netif *netif)
{
  u8_t i;

  LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer\n"));
  /* remove expired entries from the ARP table */
  for (i = 0; i < ARP_TABLE_SIZE; ++i) {

    if (arp_table[i].if_id == netif->id) {

      arp_table[i].ctime++;
      /* stable entry? */
      if ((arp_table[i].state == ETHARP_STATE_STABLE) &&
        /* entry has become old? */
        (arp_table[i].ctime >= ARP_MAXAGE)) {
        LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired stable entry %u.\n", i)); 
        arp_table[i].state = ETHARP_STATE_EXPIRED;
        /* pending entry? */
      } else if (arp_table[i].state == ETHARP_STATE_PENDING) {
        /* entry unresolved/pending for too long? */
        if (arp_table[i].ctime >= ARP_MAXPENDING) {
          LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer: expired pending entry %u.\n", i));
          arp_table[i].state = ETHARP_STATE_EXPIRED;
#if ARP_QUEUEING
        } else if (arp_table[i].p != NULL) {
        /* resend an ARP query here */
#endif           	
        }
      }
      /* clean up entries that have just been expired */
      if (arp_table[i].state == ETHARP_STATE_EXPIRED) {
#if ARP_QUEUEING
        /* and empty packet queue */
        if (arp_table[i].p != NULL) {
          /* remove all queued packets */
          LWIP_DEBUGF(ETHARP_DEBUG, ("etharp_timer: freeing entry %u, packet queue %p.\n", i, (void *)(arp_table[i].p)));
          pbuf_free(arp_table[i].p);
          arp_table[i].p = NULL;
        }
#endif
        /* recycle entry for re-use */      
        arp_table[i].state = ETHARP_STATE_EMPTY;
      }
    }
  }
}

/**
 * Search the ARP table for a matching or new entry.
 * 
 * If an IP address is given, return a pending or stable ARP entry that matches
 * the address. If no match is found, create a new entry with this address set,
 * but in state ETHARP_EMPTY. The caller must check and possibly change the
 * state of the returned entry.
 * 
 * If ipaddr is NULL, return a initialized new entry in state ETHARP_EMPTY.
 * 
 * In all cases, attempt to create new entries from an empty entry. If no
 * empty entries are available and ETHARP_TRY_HARD flag is set, recycle
 * old entries. Heuristic choose the least important entry for recycling.
 *
 * @param ipaddr IP address to find in ARP cache, or to add if not found.
 * @param flags
 * - ETHARP_TRY_HARD: Try hard to create a entry by allowing recycling of
 * active (stable or pending) entries.
 *  
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
static s8_t find_entry(struct ip_addr *ipaddr, u8_t flags)
{
  s8_t old_pending = ARP_TABLE_SIZE, old_stable = ARP_TABLE_SIZE;
  s8_t empty = ARP_TABLE_SIZE;
  u8_t i = 0, age_pending = 0, age_stable = 0;
#if ARP_QUEUEING
  /* oldest entry with packets on queue */
  s8_t old_queue = ARP_TABLE_SIZE;
  /* its age */
  u8_t age_queue = 0;
#endif

  /**
   * a) do a search through the cache, remember candidates
   * b) select candidate entry
   * c) create new entry
   */

  /* a) in a single search sweep, do all of this
   * 1) remember the first empty entry (if any)
   * 2) remember the oldest stable entry (if any)
   * 3) remember the oldest pending entry without queued packets (if any)
   * 4) remember the oldest pending entry with queued packets (if any)
   * 5) search for a matching IP entry, either pending or stable
   *    until 5 matches, or all entries are searched for.
   */

  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    /* no empty entry found yet and now we do find one? */
    if ((empty == ARP_TABLE_SIZE) && (arp_table[i].state == ETHARP_STATE_EMPTY)) {
      LWIP_DEBUGF(ETHARP_DEBUG, ("find_entry: found empty entry %d\n", i));
      /* remember first empty entry */
      empty = i;
    }
    /* pending entry? */
    else if (arp_table[i].state == ETHARP_STATE_PENDING) {
      /* if given, does IP address match IP address in ARP entry? */
      if (ipaddr && ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
        LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: found matching pending entry %d\n", i));
        /* found exact IP address match, simply bail out */
        return i;
#if ARP_QUEUEING
      /* pending with queued packets? */
      } else if (arp_table[i].p != NULL) {
        if (arp_table[i].ctime >= age_queue) {
          old_queue = i;
          age_queue = arp_table[i].ctime;
        }
#endif
      /* pending without queued packets? */
      } else {
        if (arp_table[i].ctime >= age_pending) {
          old_pending = i;
          age_pending = arp_table[i].ctime;
        }
      }        
    }
    /* stable entry? */
    else if (arp_table[i].state == ETHARP_STATE_STABLE) {
      /* if given, does IP address match IP address in ARP entry? */
      if (ipaddr && ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
        LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: found matching stable entry %d\n", i));
        /* found exact IP address match, simply bail out */
        return i;
      /* remember entry with oldest stable entry in oldest, its age in maxtime */
      } else if (arp_table[i].ctime >= age_stable) {
        old_stable = i;
        age_stable = arp_table[i].ctime;
      }
    }
  }
  /* { we have no match } => try to create a new entry */
   
  /* no empty entry found and not allowed to recycle? */
  if ((empty == ARP_TABLE_SIZE) && ((flags & ETHARP_TRY_HARD) == 0))
  {
  	return (s8_t)ERR_MEM;
  }
  
  /* b) choose the least destructive entry to recycle:
   * 1) empty entry
   * 2) oldest stable entry
   * 3) oldest pending entry without queued packets
   * 4) oldest pending entry without queued packets
   * 
   * { ETHARP_TRY_HARD is set at this point }
   */ 

  /* 1) empty entry available? */
  if (empty < ARP_TABLE_SIZE) {
    i = empty;
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: selecting empty entry %d\n", i));
  }
  /* 2) found recyclable stable entry? */
  else if (old_stable < ARP_TABLE_SIZE) {
    /* recycle oldest stable*/
    i = old_stable;
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: selecting oldest stable entry %d\n", i));
#if ARP_QUEUEING
    /* no queued packets should exist on stable entries */
    LWIP_ASSERT("arp_table[i].p == NULL", arp_table[i].p == NULL);
#endif
  /* 3) found recyclable pending entry without queued packets? */
  } else if (old_pending < ARP_TABLE_SIZE) {
    /* recycle oldest pending */
    i = old_pending;
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: selecting oldest pending entry %d (without queue)\n", i));
#if ARP_QUEUEING
  /* 4) found recyclable pending entry with queued packets? */
  } else if (old_queue < ARP_TABLE_SIZE) {
    /* recycle oldest pending */
    i = old_queue;
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("find_entry: selecting oldest pending entry %d, freeing packet queue %p\n", i, (void *)(arp_table[i].p)));
    pbuf_free(arp_table[i].p);
    arp_table[i].p = NULL;
#endif
    /* no empty or recyclable entries found */
  } else {
    return (s8_t)ERR_MEM;
  }

  /* { empty or recyclable entry found } */
  LWIP_ASSERT("i < ARP_TABLE_SIZE", i < ARP_TABLE_SIZE);

  /* recycle entry (no-op for an already empty entry) */
  arp_table[i].state = ETHARP_STATE_EMPTY;

  /* IP address given? */
  if (ipaddr != NULL) {
    /* set IP address */
    ip_addr_set(&arp_table[i].ipaddr, ipaddr);
  }
  arp_table[i].ctime = 0;
  return (err_t)i;
}

/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 * 
 * @param ipaddr IP address of the inserted ARP entry.
 * @param ethaddr Ethernet address of the inserted ARP entry.
 * @param flags Defines behaviour:
 * - ETHARP_TRY_HARD Allows ARP to insert this as a new item. If not specified,
 * only existing ARP entries will be updated.
 *
 * @return
 * - ERR_OK Succesfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see pbuf_free()
 */
static err_t
update_arp_entry(struct netif *netif, struct ip_addr *ipaddr, struct eth_addr *ethaddr, u8_t flags)
{
  s8_t i, k;
  LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE | 3, ("update_arp_entry()\n"));
  LWIP_ASSERT("netif->hwaddr_len != 0", netif->hwaddr_len != 0);
  LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("update_arp_entry: %lu.%lu.%lu.%lu - %02x:%02x:%02x:%02x:%02x:%02x\n",
                                        ip4_addr1(ipaddr), ip4_addr2(ipaddr), ip4_addr3(ipaddr), ip4_addr4(ipaddr), 
                                        ethaddr->addr[0], ethaddr->addr[1], ethaddr->addr[2],
                                        ethaddr->addr[3], ethaddr->addr[4], ethaddr->addr[5]));
  /* non-unicast address? */
	/* XXX XXX XXX broadcast control on netif!*/
	if (ip_addr_isany(ipaddr) ||
      /*ip_addr_is_v4broadcast(ipaddr, &(al->ipaddr), &(al->netmask)) ||*/
      ip_addr_ismulticast(ipaddr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("update_arp_entry: will not add non-unicast IP address to ARP cache\n"));
    return ERR_ARG;
  }
  /* find or create ARP entry */
  i = find_entry(ipaddr, flags);
  /* bail out if no entry could be found */
  if (i < 0) return (err_t)i;
  
  /* mark it stable */
  arp_table[i].state = ETHARP_STATE_STABLE;

  LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("update_arp_entry: updating stable entry %u\n", i));
	//printf("%lx %lx %lx %lx\n",ipaddr->addr[0],ipaddr->addr[1],ipaddr->addr[2],ipaddr->addr[3]);
  /* update address */
  for (k = 0; k < netif->hwaddr_len; ++k) {
    arp_table[i].ethaddr.addr[k] = ethaddr->addr[k];
  }
	arp_table[i].if_id=netif->id;
  /* reset time stamp */
  arp_table[i].ctime = 0;
/* this is where we will send out queued packets! */
#if ARP_QUEUEING
  while (arp_table[i].p != NULL) {
    /* get the first packet on the queue */
    struct pbuf *p = arp_table[i].p;
    /* Ethernet header */
    struct eth_hdr *ethhdr = p->payload;
    /* remember (and reference) remainder of queue */
    /* note: this will also terminate the p pbuf chain */
    arp_table[i].p = pbuf_dequeue(p);
    /* fill-in Ethernet header */
    for (k = 0; k < netif->hwaddr_len; ++k) {
      ethhdr->dest.addr[k] = ethaddr->addr[k];
      ethhdr->src.addr[k] = netif->hwaddr[k];
    }
    // Fix by Renzo Davoli
    //    ethhdr->type = htons(ETHTYPE_IP); 
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("update_arp_entry: sending queued IP packet %p.\n", (void *)p));
    /* send the queued IP packet */
    LINKOUTPUT(netif, p);
    /* free the queued IP packet */
    pbuf_free(p);
  }
#endif
  return ERR_OK;
}

/**
 * Updates the ARP table using the given IP packet.
 *
 * Uses the incoming IP packet's source address to update the
 * ARP cache for the local network. The function does not alter
 * or free the packet. This function must be called before the
 * packet p is passed to the IP layer.
 *
 * @param netif The lwIP network interface on which the IP packet pbuf arrived.
 * @param pbuf The IP packet that arrived on netif.
 *
 * @return NULL
 *
 * @see pbuf_free()
 */
static void
etharp_ip4_input(struct netif *netif, struct pbuf *p)
{
  struct ethip4_hdr *hdr;
  struct ip_addr src4;

  /* Only insert an entry if the source IP address of the
     incoming IP packet comes from a host on the local network. */
  hdr = p->payload;
  IP64_CONV(&src4,&(hdr->ip.src));
  if (!ip_addr_list_maskfind(netif->addrs, &(src4))) {
    /* do nothing */
    return;
  }

  LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_ip4_input: updating ETHARP table.\n"));
  /* update ARP table, ask to insert entry */
  update_arp_entry(netif, &(src4), &(hdr->eth.src), ARP_INSERT_FLAG);
  return;
}

void
etharp_ip_input(struct netif *netif, struct pbuf *p)
{
  struct ethip_hdr *hdr;
  LWIP_ASSERT("netif != NULL", netif != NULL);
  /* Only insert an entry if the source IP address of the
     incoming IP packet comes from a host on the local network. */
  hdr = p->payload;
  if (hdr->eth.type == ETHTYPE_IP)
    etharp_ip4_input(netif,p);

  if (!ip_addr_list_maskfind(netif->addrs, &(hdr->ip.src))) {
    /* do nothing */
    return;
  }

  LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_ip_input: updating ETHARP table.\n"));
  /* update ARP table */
  /* @todo We could use ETHARP_TRY_HARD if we think we are going to talk
   * back soon (for example, if the destination IP address is ours. */
  update_arp_entry(netif, &(hdr->ip.src), &(hdr->eth.src), ARP_INSERT_FLAG);
}


/**
 * Responds to ARP requests to us. Upon ARP replies to us, add entry to cache  
 * send out queued IP packets. Updates cache with snooped address pairs.
 *
 * Should be called for incoming ARP packets. The pbuf in the argument
 * is freed by this function.
 *
 * @param netif The lwIP network interface on which the ARP packet pbuf arrived.
 * @param pbuf The ARP packet that arrived on netif. Is freed by this function.
 * @param ethaddr Ethernet address of netif.
 *
 * @return NULL
 *
 * @see pbuf_free()
 */
void
etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
{
  struct etharp_hdr *hdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
	struct ip_addr_list *el;
	struct ip_addr v4dipaddr,v4sipaddr;
  u8_t i;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  
  /* drop short ARP packets */
  if (p->tot_len < sizeof(struct etharp_hdr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE | 1, ("etharp_arp_input: packet dropped, too short (%d/%d)\n", p->tot_len, sizeof(struct etharp_hdr)));
    pbuf_free(p);
    return;
  }

  hdr = p->payload;
 
	IP64_CONV(&v4dipaddr,&(hdr->dipaddr));
	IP64_CONV(&v4sipaddr,&(hdr->sipaddr));
	el= ip_addr_list_find(netif->addrs,&v4dipaddr,NULL);

  /* ARP message directed to us? */
  if (el != NULL) {
    /* add IP address in ARP cache; assume requester wants to talk to us.
     * can result in directly sending the queued packets for this host. */
    update_arp_entry(netif, &v4sipaddr, &(hdr->shwaddr), ETHARP_TRY_HARD);
  /* ARP message not directed to us? */
  } else {
    /* update the source IP address in the cache, if present */
    update_arp_entry(netif, &v4sipaddr, &(hdr->shwaddr), 0);
  }

  /* now act on the message itself */
  switch (htons(hdr->opcode)) {
  /* ARP request? */
  case ARP_REQUEST:
    /* ARP request. If it asked for our address, we send out a
     * reply. In any case, we time-stamp any existing ARP entry,
     * and possiby send out an IP packet that was queued on it. */

    LWIP_DEBUGF (ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: incoming ARP request\n"));
    /* ARP request for our address? */
    if (el != NULL) {

      LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: replying to ARP request for our IP address\n"));
      /* re-use pbuf to send ARP reply */
      hdr->opcode = htons(ARP_REPLY);

      /*hdr->dipaddr = hdr->sipaddr;
      hdr->sipaddr = *(struct ip_addr2 *)&netif->ip_addr;*/
			ip4_addr_set(&(hdr->dipaddr), &(hdr->sipaddr));
			ip64_addr_set(&(hdr->sipaddr), &(el->ipaddr));


      for(i = 0; i < netif->hwaddr_len; ++i) {
        hdr->dhwaddr.addr[i] = hdr->shwaddr.addr[i];
        hdr->shwaddr.addr[i] = ethaddr->addr[i];
        hdr->ethhdr.dest.addr[i] = hdr->dhwaddr.addr[i];
        hdr->ethhdr.src.addr[i] = ethaddr->addr[i];
      }

      hdr->hwtype = htons(HWTYPE_ETHERNET);
      ARPH_HWLEN_SET(hdr, netif->hwaddr_len);

      hdr->proto = htons(ETHTYPE_IP);
      ARPH_PROTOLEN_SET(hdr, sizeof(struct ip4_addr));

      hdr->ethhdr.type = htons(ETHTYPE_ARP);
      /* return ARP reply */
      LINKOUTPUT(netif, p);
    /* we are not configured? */
    } 
#if 0
		else if (netif->ip_addr.addr == 0) {
      /* { for_us == 0 and netif->ip_addr.addr == 0 } */
      LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: we are unconfigured, ARP request ignored.\n"));
    /* request was not directed to us */
    } 
#endif
		else {
      /* { for_us == 0 and netif->ip_addr.addr != 0 } */
      LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: ARP request was not for us.\n"));
    }
    break;
  case ARP_REPLY:
    /* ARP reply. We already updated the ARP cache earlier. */
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: incoming ARP reply\n"));

#if (LWIP_DHCP && DHCP_DOES_ARP_CHECK)
    /* DHCP wants to know about ARP replies from any host with an
     * IP address also offered to us by the DHCP server. We do not
     * want to take a duplicate IP address on a single network.
     * @todo How should we handle redundant (fail-over) interfaces?
     * */
    ///dhcp_arp_reply(netif, &sipaddr);
    dhcp_arp_reply(netif, (struct ip4_addr *) &(hdr->sipaddr));
#endif

    break;

  default:
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_arp_input: ARP unknown opcode type %d\n", htons(hdr->opcode)));
    break;
  }
  /* free ARP packet */
  pbuf_free(p);
}

/**
 * Resolve and fill-in Ethernet address header for outgoing packet.
 *
 * For IP multicast and broadcast, corresponding Ethernet addresses
 * are selected and the packet is transmitted on the link.
 *
 * For unicast addresses, the packet is submitted to etharp_query(). In
 * case the IP address is outside the local network, the IP address of
 * the gateway is used.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param ipaddr The IP address of the packet destination.
 * @param pbuf The pbuf(s) containing the IP packet to be sent.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or netif->linkoutput().
 */
err_t
etharp_output(struct netif *netif, struct ip_addr *ipaddr, struct pbuf *q)
{
	struct eth_addr *dest, *srcaddr, mcastaddr;
	struct ip_addr_list *al;
	struct eth_hdr *ethhdr;
	u8_t i;
	
	/* make room for Ethernet header - should not fail */
	if (pbuf_header(q, sizeof(struct eth_hdr)) != 0) {
		/* bail out */
		LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE | 2, ("etharp_output: could not allocate room for header.\n"));
		LINK_STATS_INC(link.lenerr);
		printf("etharp_output ERR\n");
		return ERR_BUF;
	}

	/* assume unresolved Ethernet address */
	dest = NULL;
	/* Determine on destination hardware address. Broadcasts and multicasts
	 * are special, other IP addresses are looked up in the ARP table. */

	/* broadcast destination IP address? */
	if (ip_addr_is_v4comp(ipaddr)) {

		/* destination IP address is an IP multicast address? */
		if (ip_addr_is_v4multicast(ipaddr)) {

			/* Hash IP multicast address to MAC address. */
			mcastaddr.addr[0] = 0x01;
			mcastaddr.addr[1] = 0x00;
			mcastaddr.addr[2] = 0x5e;
			mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
			mcastaddr.addr[4] = ip4_addr3(ipaddr);
			mcastaddr.addr[5] = ip4_addr4(ipaddr);
			/* destination Ethernet address is multicast */
			dest = &mcastaddr;
			/* unicast destination IP address? */
		} 
		/// CHANGED BY DIEGO BILLI
		else if (ip_addr_is_v4broadcast_allones(ipaddr)) {
			dest = (struct eth_addr *)&ethbroadcast;
		}
		else {

			/* destination IP network address not on local network?
			*        * IP layer wants us to forward to the default gateway */
			if ((al=ip_addr_list_maskfind(netif->addrs, ipaddr)) == NULL) {
				return -1;
			}
			/* destination IP address is an IP broadcast address? */
			if (ip_addr_isany(ipaddr) || ip_addr_is_v4broadcast(ipaddr, &(al->ipaddr), &(al->netmask))) {
				/* broadcast on Ethernet also */
				dest = (struct eth_addr *)&ethbroadcast;
			}
		}
	}
	else {
		if (ip_addr_isany(ipaddr) || ip_addr_ismulticast(ipaddr)) {
			mcastaddr.addr[0] = 0x33;
			mcastaddr.addr[1] = 0x33;
			mcastaddr.addr[2] = 0xff;
			mcastaddr.addr[3] = ipaddr->addr[3] >> 16 & 0xff;
			mcastaddr.addr[4] = ipaddr->addr[3] >> 8 & 0xff;
			mcastaddr.addr[5] = ipaddr->addr[3] & 0xff;
			dest = &mcastaddr;
		}
		/* destination IP network address not on local network?
		* IP layer wants us to forward to the default gateway */
		else if ((al=ip_addr_list_maskfind(netif->addrs, ipaddr)) == NULL) {
		
			//printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
			return ERR_RTE;
		}

		//printf("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL");

	}

	/* XXX XXX XXX */
	
	if (dest == NULL) {
		/* Ethernet address for IP destination address is in ARP cache? */
		for (i = 0; i < ARP_TABLE_SIZE; ++i) {
			/* match found? */
			if (arp_table[i].state == ETHARP_STATE_STABLE && ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) {
				dest = &arp_table[i].ethaddr;
				break;
			}
		}
		/* could not find the destination Ethernet address in ARP cache? */
		if (dest == NULL) {
			/* ARP query for the IP address, submit this IP packet for queueing */
			/* TODO: How do we handle netif->ipaddr == ipaddr? */
			etharp_query(al, ipaddr, q);
			/* { packet was queued (ERR_OK), or discarded } */
			/* return nothing */
	
			/*printf("QUERY NULL!\n");*/
			return ERR_RTE; /*???*/
		}
		/* destination Ethernet address resolved from ARP cache */
		else
		{
			/* fallthrough */
		}
	}
	/* destination Ethernet address known */
	if (dest != NULL) {
		/* obtain source Ethernet address of the given interface */
		srcaddr = (struct eth_addr *)netif->hwaddr;
	
		/* A valid IP->MAC address mapping was found, fill in the
		 * Ethernet header for the outgoing packet */
		ethhdr = q->payload;
		if (ip_addr_is_v4comp(ipaddr))
			ethhdr->type = htons(ETHTYPE_IP);
		else    	
			ethhdr->type = htons(ETHTYPE_IP6);
	
		for(i = 0; i < netif->hwaddr_len; i++) {
			ethhdr->dest.addr[i] = dest->addr[i];
			ethhdr->src.addr[i]  = srcaddr->addr[i];
		}
	
		/* return the outgoing packet */
		return LINKOUTPUT(netif, q);
	}

	/* never reached; here for safety */
	return 0;
}

#if 0
{
	{
    /* queue on destination Ethernet address belonging to ipaddr */
    return etharp_query(netif, ipaddr, q);
  }

  /* continuation for multicast/broadcast destinations */
  /* obtain source Ethernet address of the given interface */
  srcaddr = (struct eth_addr *)netif->hwaddr;
  ethhdr = q->payload;
  for (i = 0; i < netif->hwaddr_len; i++) {
    ethhdr->dest.addr[i] = dest->addr[i];
    ethhdr->src.addr[i] = srcaddr->addr[i];
  }
  ethhdr->type = htons(ETHTYPE_IP);
  /* send packet directly on the link */
  return netif->linkoutput(netif, q);
}
#endif

/**
 * Send an ARP request for the given IP address and/or queue a packet.
 *
 * If the IP address was not yet in the cache, a pending ARP cache entry
 * is added and an ARP request is sent for the given address. The packet
 * is queued on this entry.
 *
 * If the IP address was already pending in the cache, a new ARP request
 * is sent for the given address. The packet is queued on this entry.
 *
 * If the IP address was already stable in the cache, and a packet is
 * given, it is directly sent and no ARP request is sent out. 
 * 
 * If the IP address was already stable in the cache, and no packet is
 * given, an ARP request is sent out.
 * 
 * @param netif The lwIP network interface on which ipaddr
 * must be queried for.
 * @param ipaddr The IP address to be resolved.
 * @param q If non-NULL, a pbuf that must be delivered to the IP address.
 * q is not freed by this function.
 *
 * @return
 * - ERR_BUF Could not make room for Ethernet header.
 * - ERR_MEM Hardware address unknown, and no more ARP entries available
 *   to query for address or queue the packet.
 * - ERR_MEM Could not queue packet due to memory shortage.
 * - ERR_RTE No route to destination (no gateway to external networks).
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 */
err_t etharp_query(struct ip_addr_list *al, struct ip_addr *ipaddr, struct pbuf *q)
{
  struct pbuf *p;
	struct netif *netif=al->netif;
  struct eth_addr * srcaddr = (struct eth_addr *)netif->hwaddr;
  err_t result = ERR_MEM;

  s8_t i; /* ARP entry index */
  u8_t k; /* Ethernet address octet index */

  /* non-unicast address? */
  if (ip_addr_is_v4broadcast(ipaddr, &(al->ipaddr), &(al->netmask)) ||
      ip_addr_ismulticast(ipaddr) ||
      ip_addr_isany(ipaddr)) {
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: will not add non-unicast IP address to ARP cache\n"));
    return ERR_ARG;
  }

  /* find entry in ARP cache, ask to create entry if queueing packet */
  i = find_entry(ipaddr, ETHARP_TRY_HARD);

  /* could not find or create entry? */
  if (i < 0)
  {
    LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: could not create ARP entry\n"));
    if (q) LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: packet dropped\n"));
    return (err_t)i;
  }

  /* mark a fresh entry as pending (we just sent a request) */
  if (arp_table[i].state == ETHARP_STATE_EMPTY) {
    arp_table[i].state = ETHARP_STATE_PENDING;
  }

  /* { i is either a STABLE or (new or existing) PENDING entry } */
  LWIP_ASSERT("arp_table[i].state == PENDING or STABLE",
  ((arp_table[i].state == ETHARP_STATE_PENDING) ||
   (arp_table[i].state == ETHARP_STATE_STABLE)));

  /* do we have a pending entry? or an implicit query request? */
  if ((arp_table[i].state == ETHARP_STATE_PENDING) || (q == NULL)) {
    /* try to resolve it; send out ARP request */
    result = etharp_request(al, ipaddr);
  }
  
  /* packet given? */
  if (q != NULL) {

	// Added by Renzo Davoli
	struct eth_hdr *ethhdr = q->payload;
	if (ip_addr_is_v4comp(ipaddr))
		ethhdr->type = htons(ETHTYPE_IP);
	else
		ethhdr->type = htons(ETHTYPE_IP6);


    /* stable entry? */
    if (arp_table[i].state == ETHARP_STATE_STABLE) {
      /* we have a valid IP->Ethernet address mapping,
       * fill in the Ethernet header for the outgoing packet */
// Fix by Renzo Davoli
//    struct eth_hdr *ethhdr = q->payload; 
      for(k = 0; k < netif->hwaddr_len; k++) {
        ethhdr->dest.addr[k] = arp_table[i].ethaddr.addr[k];
        ethhdr->src.addr[k]  = srcaddr->addr[k];
      }
// Fix by Renzo Davoli
//			if (ip_addr_is_v4comp(ipaddr))
//				ethhdr->type = htons(ETHTYPE_IP);
//			else
//				ethhdr->type = htons(ETHTYPE_IP6);
      LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: sending packet %p\n", (void *)q));
      /* send the packet */
      LINKOUTPUT(netif, q);
    /* pending entry? (either just created or already pending */
    } else if (arp_table[i].state == ETHARP_STATE_PENDING) {
#if ARP_QUEUEING /* queue the given q packet */
      /* copy any PBUF_REF referenced payloads into PBUF_RAM */
      /* (the caller of lwIP assumes the referenced payload can be
       * freed after it returns from the lwIP call that brought us here) */
      p = pbuf_take(q);
      /* packet could be taken over? */
      if (p != NULL) {
        /* queue packet ... */
        if (arp_table[i].p == NULL) {
        	/* ... in the empty queue */
        	pbuf_ref(p);
        	arp_table[i].p = p;
#if 0 /* multi-packet-queueing disabled, see bug #11400 */
        } else {
        	/* ... at tail of non-empty queue */
          pbuf_queue(arp_table[i].p, p);
#endif
        }
        LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: queued packet %p on ARP entry %d\n", (void *)q, i));
        result = ERR_OK;
      } else {
        LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: could not queue a copy of PBUF_REF packet %p (out of memory)\n", (void *)q));
        /* { result == ERR_MEM } through initialization */
      }
#else /* ARP_QUEUEING == 0 */
      /* q && state == PENDING && ARP_QUEUEING == 0 => result = ERR_MEM */
      /* { result == ERR_MEM } through initialization */
      LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_query: Ethernet destination address unknown, queueing disabled, packet %p dropped\n", (void *)q));
#endif
    }
  }
  return result;
}

err_t etharp_request(struct ip_addr_list *al, struct ip_addr *ipaddr)
{
	struct netif *netif=al->netif;
	struct eth_addr * srcaddr = (struct eth_addr *)netif->hwaddr;
	err_t result = ERR_OK;
	u8_t k; /* ARP entry index */

	if (ip_addr_is_v4comp(ipaddr)) {
		struct pbuf *p;
		/* allocate a pbuf for the outgoing ARP request packet */
		p = pbuf_alloc(PBUF_LINK, sizeof(struct etharp_hdr), PBUF_RAM);
		/* could allocate a pbuf for an ARP request? */
		if (p != NULL) {
			struct etharp_hdr *hdr = p->payload;
			LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE, ("etharp_request: sending ARP request.\n"));
			hdr->opcode = htons(ARP_REQUEST);
			for (k = 0; k < netif->hwaddr_len; k++)
			{
				hdr->shwaddr.addr[k] = srcaddr->addr[k];
				/* the hardware address is what we ask for, in
				 * a request it is a don't-care value, we use zeroes */
				hdr->dhwaddr.addr[k] = 0x00;
			}
			ip64_addr_set(&(hdr->dipaddr), ipaddr);
			ip64_addr_set(&(hdr->sipaddr), &(al->ipaddr));

			hdr->hwtype = htons(HWTYPE_ETHERNET);
			ARPH_HWLEN_SET(hdr, netif->hwaddr_len);

			hdr->proto = htons(ETHTYPE_IP);
			ARPH_PROTOLEN_SET(hdr, sizeof(struct ip4_addr));
			for (k = 0; k < netif->hwaddr_len; ++k)
			{
				/* broadcast to all network interfaces on the local network */
				hdr->ethhdr.dest.addr[k] = 0xff;
				hdr->ethhdr.src.addr[k] = srcaddr->addr[k];
			}
			hdr->ethhdr.type = htons(ETHTYPE_ARP);
			/* send ARP query */
			result = LINKOUTPUT(netif, p);
			/* free ARP query packet */
			pbuf_free(p);
			p = NULL;
			/* could not allocate pbuf for ARP request */
		} else {
			result = ERR_MEM;
			LWIP_DEBUGF(ETHARP_DEBUG | DBG_TRACE | 2, ("etharp_request: could not allocate pbuf for ARP request.\n"));
		}
	} else {
		icmp_neighbor_solicitation(ipaddr, al);
	}
  return result;
}

#if LWIP_PACKET
void eth_packet_mgmt(struct netif *netif, struct pbuf *p,u8_t pkttype)
{
	struct sockaddr_ll sll;
	struct eth_hdr *eh=p->payload;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_protocol = ntohs(eh->type);
	sll.sll_hatype = ARPHRD_ETHER;
	sll.sll_ifindex = netif->id;
	memcpy(sll.sll_addr,&(eh->src),sizeof(struct eth_addr));
	if (pkttype != 0) 
		sll.sll_pkttype = pkttype;
	else {
		if (memcmp(&(eh->dest),netif->hwaddr,sizeof(struct eth_addr))==0) 
			sll.sll_pkttype = PACKET_HOST;
		else if (memcmp(&(eh->dest),&ethbroadcast,sizeof(struct eth_addr))==0) 
			sll.sll_pkttype = PACKET_BROADCAST;
		else if (eh->dest.addr[0] & 1)
			sll.sll_pkttype = PACKET_MULTICAST;
		else
			sll.sll_pkttype = PACKET_OTHERHOST;
	}
  packet_input(p,&sll,sizeof(struct eth_hdr));
}

u16_t eth_packet_out(struct netif *netif, struct pbuf *p, struct sockaddr_ll *sll, u16_t protocol, u16_t dgramflag)
{
	struct pbuf *q; /* q will be sent down the stack */
	if (dgramflag) {
		if (pbuf_header(p, sizeof(struct eth_hdr))) { /* XXX */
			/* allocate header in new pbuf */
			q = pbuf_alloc(PBUF_LINK, 0, PBUF_RAM);
			/* new header pbuf could not be allocated? */
			if (q == NULL) {
				LWIP_DEBUGF(PACKET_DEBUG | DBG_TRACE | 2, ("packet_sendto: could not allocate header\n"));
				return ERR_MEM;
			}
			/* chain header q in front of given pbuf p */
			pbuf_chain(q, p);
			/* { first pbuf q points to header pbuf } */
			LWIP_DEBUGF(PACKET_DEBUG, ("packet_sendto: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));
			pbuf_header(q, sizeof(struct eth_hdr));
		}  else {
			/* first pbuf q equals given pbuf */
			q = p;
		}
		struct eth_hdr *eh=(struct eth_hdr *)q->payload;
		memcpy(&eh->dest,sll->sll_addr,sizeof(struct eth_addr));
		memcpy(&eh->src,netif->hwaddr,sizeof(struct eth_addr));
		eh->type=htons(protocol);
	} else
		q=p;
	
	netif->linkoutput(netif,q);
	/* did we chain a header earlier? */
	if (q != p) {
		/* free the header */
		pbuf_free(q);
	}
	return ERR_OK;
}
#endif
