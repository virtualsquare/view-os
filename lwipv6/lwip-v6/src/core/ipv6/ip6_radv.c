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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef IPv6_ROUTER_ADVERTISEMENT

#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"

#include "lwip/icmp.h"
#include "lwip/ip_radv.h"
#include "lwip/radvconf.h"

#include "lwip/netlinkdefs.h"

/* Rfc 2461 - Neighbor Discovery for IP Version 6 (IPv6) */

#ifndef IP_RADV_DEBUG
#define IP_RADV_DEBUG     DBG_OFF
#endif

#define U_INT  (unsigned int)

/*--------------------------------------------------------------------------*/

void ip_radv_prefix_dump(struct radv_prefix *prefix)
{
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\t")); ip_addr_debug_print(IP_RADV_DEBUG, &prefix->Prefix);
	LWIP_DEBUGF(IP_RADV_DEBUG, (" / %d \n", prefix->PrefixLen));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\t\tAdvOnLinkFlag        = %d\n", prefix->AdvOnLinkFlag ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\t\tAdvAutonomousFlag    = %d\n", prefix->AdvAutonomousFlag ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\t\tAdvValidLifetime     = %d\n", U_INT prefix->AdvValidLifetime ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\t\tAdvPreferredLifetime = %d\n", U_INT prefix->AdvPreferredLifetime ));
}
void ip_radv_data_dump(struct radv *rinfo)
{
	struct radv_prefix *prefix;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvSendAdvert      = %d\n", rinfo->AdvSendAdvert  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tUnicastOnly        = %d\n", rinfo->UnicastOnly  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvManagedFlag     = %d\n", U_INT rinfo->AdvManagedFlag  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvOtherConfigFlag = %d\n", U_INT rinfo->AdvOtherConfigFlag  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tMaxRtrAdvInterval  = %d\n", U_INT rinfo->MaxRtrAdvInterval  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tMinRtrAdvInterval  = %d\n", U_INT rinfo->MinRtrAdvInterval  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tMinDelayBetweenRAs = %d\n", U_INT rinfo->MinDelayBetweenRAs  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvRetransTimer    = %d\n", U_INT rinfo->AdvRetransTimer  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvReachableTime   = %d\n", U_INT rinfo->AdvReachableTime  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvDefaultLifetime = %d\n", U_INT rinfo->AdvDefaultLifetime  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvCurHopLimit     = %d\n", rinfo->AdvCurHopLimit  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvLinkMTU         = %d\n", U_INT  rinfo->AdvLinkMTU  ));
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvSourceLLAddress = %d\n", rinfo->AdvSourceLLAddress  ));

	prefix = rinfo->prefix_list;
	while (prefix) {
		ip_radv_prefix_dump(prefix);
		prefix = prefix->next;
	}
}

/*--------------------------------------------------------------------------*/


#define PREFIx_POOL_SIZE   10

static struct radv_prefix prefix_pool[PREFIx_POOL_SIZE];
static struct radv_prefix *prefix_freelist;

void radv_prefix_list_init(void)
{
	int i;

	for (i=0; i<PREFIx_POOL_SIZE-1; i++)
		prefix_pool[i].next = &prefix_pool[i+1];

	prefix_pool[i].next = NULL;
	prefix_freelist = prefix_pool;
}

void ip_radv_prefix_init(struct radv_prefix *prefix);

struct radv_prefix *radv_prefix_list_alloc()
{
	struct radv_prefix *el;

	if (prefix_freelist == NULL)
		return NULL;
	else {
		el = prefix_freelist;
		prefix_freelist = prefix_freelist->next;

		ip_radv_prefix_init(el);

		return el;
	}
}

void radv_prefix_list_free(struct radv_prefix *el)
{
	el->next        = prefix_freelist;
	prefix_freelist = el;
}


void ip_radv_prefix_init(struct radv_prefix *prefix)
{
	memset(prefix, 0, sizeof(struct radv_prefix));
	//prefix->Prefix, prefix->PrefixLen
	prefix->AdvOnLinkFlag        = DFLT_AdvOnLinkFlag;
	prefix->AdvAutonomousFlag    = DFLT_AdvAutonomousFlag;
	prefix->AdvValidLifetime     = DFLT_AdvValidLifetime;
	prefix->AdvPreferredLifetime = DFLT_AdvPreferredLifetime;
}

/*--------------------------------------------------------------------------*/

void ip_radv_data_init(struct radv *rinfo)
{
	bzero((char*)rinfo, sizeof(struct radv));

	rinfo->AdvSendAdvert	    = DFLT_AdvSendAdv;
	rinfo->AdvManagedFlag       = DFLT_AdvManagedFlag;
	rinfo->AdvOtherConfigFlag   = DFLT_AdvOtherConfigFlag;
	rinfo->MaxRtrAdvInterval    = DFLT_MaxRtrAdvInterval;
	rinfo->MinDelayBetweenRAs   = DFLT_MinDelayBetweenRAs;
	rinfo->MinRtrAdvInterval    = DFLT_MinRtrAdvInterval(rinfo);
	rinfo->AdvLinkMTU	    = DFLT_AdvLinkMTU;
	rinfo->AdvSourceLLAddress   = DFLT_AdvSourceLLAddress;
	rinfo->AdvReachableTime	    = DFLT_AdvReachableTime;
	rinfo->AdvRetransTimer      = DFLT_AdvRetransTimer;
	rinfo->AdvCurHopLimit	    = DFLT_AdvCurHopLimit;
	rinfo->AdvSourceLLAddress   = DFLT_AdvSourceLLAddress;
	rinfo->AdvDefaultLifetime   = DFLT_AdvDefaultLifetime(rinfo);
	rinfo->UnicastOnly          = DFLT_UnicastOnly;
}

void ip_radv_data_reset(struct radv *rinfo)
{
	struct radv_prefix *el, *next;

	el = rinfo->prefix_list;
	while (el) {
		next = el->next;
        	radv_prefix_list_free(el);
		el = next;
	} 

	ip_radv_data_init(rinfo);
}

void ip_radv_netif_init(struct netif *netif) 
{
	struct radv *rinfo;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: init '%c%c%d'.\n", __func__, netif->name[0], netif->name[1], netif->num) );

	rinfo = &(netif->radv);

	ip_radv_data_init(rinfo);
}

void ip_radv_netif_reset(struct netif *netif) 
{
	struct radv *rinfo;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: reset '%c%c%d'.\n", __func__, netif->name[0], netif->name[1], netif->num) );

	rinfo = &(netif->radv);

	ip_radv_data_reset(rinfo);
}

/*--------------------------------------------------------------------------*/

static double rand_between(double lower, double upper)
{
	return ((upper - lower) / (RAND_MAX + 1.0) * rand() + lower);
}

static int ip_forwarding_enabled(void)
{
#if IP_FORWARD
	return 1;
#else
	return 0;
#endif
}

void send_ra(struct netif *netif, struct ip_addr *rs_ipsrc)
{
	int totlen;
	struct radv_prefix *list;

	struct pbuf *p;
	struct icmp_ra_hdr *rahdr;
	struct icmp_opt_prefix *opt_prefix;
	struct icmp_opt_mtu    *opt_mtu;
	struct icmp_opt_addr   *opt_addr;

	struct ip_addr srcip;
	struct ip_addr dstip;


	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: start \n", __func__) );

	/*
	 * Set IP addresses
	 */

	if (rs_ipsrc != NULL && !ip_addr_isunspecified(rs_ipsrc)) {
		ip_addr_set (&dstip, rs_ipsrc);
	}
	else
		IP6_ADDR_ALLNODE(&dstip, IP6_LINKLOCAL);

	IP6_ADDR_LINKSCOPE(&srcip, netif->hwaddr);

	/*
	 * Calculate ICMP packet size
	 */
	totlen = sizeof(struct icmp_ra_hdr);

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tLenght = RA(%d)", totlen) );

	list = netif->radv.prefix_list;
	while (list != NULL) {
		totlen += sizeof(struct icmp_opt_prefix);
		LWIP_DEBUGF(IP_RADV_DEBUG, ("+Prefix(%d)", totlen) );
		list = list->next;
	}	

	if (netif->radv.AdvLinkMTU != 0) {
		totlen += sizeof(struct icmp_opt_mtu);
		LWIP_DEBUGF(IP_RADV_DEBUG, ("+MTU(%d)", totlen) );
	}

	if (netif->radv.AdvSourceLLAddress == TRUE) {
		totlen += sizeof(struct icmp_opt_addr) + netif->hwaddr_len;
		LWIP_DEBUGF(IP_RADV_DEBUG, ("+LLAddr(%d)", totlen) );
	}
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\n") );

        /* 
	 * Create ICMP packet 
	 */
	p = pbuf_alloc(PBUF_IP, totlen , PBUF_RAM);
	if (p == NULL) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("\t*** Unable to create new packet"));
		return;
	}

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tSetting: RA") );

	bzero(p->payload, p->tot_len);

	rahdr = p->payload;
	rahdr->type      = ICMP6_RA;
	rahdr->icode     = 0;
	rahdr->hoplimit	 = netif->radv.AdvCurHopLimit;
	rahdr->m_o_flag	 = netif->radv.AdvManagedFlag     ? ICMP6_RA_M : 0;
	rahdr->m_o_flag	|= netif->radv.AdvOtherConfigFlag ? ICMP6_RA_O : 0;
	rahdr->life	 = ip_forwarding_enabled() ? htons(netif->radv.AdvDefaultLifetime) : 0;
	rahdr->reach     = htonl(netif->radv.AdvReachableTime);
	rahdr->retran    = htonl(netif->radv.AdvRetransTimer);
	rahdr++;

	/* Add MTU option */
	opt_mtu = (struct icmp_opt_mtu *) (rahdr);
	if (netif->radv.AdvLinkMTU != 0) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("+MTU") );
		opt_mtu->type     = ICMP6_OPT_MTU;
		opt_mtu->len      = 1;
		opt_mtu->reserved = 0; 
		opt_mtu->mtu      = htonl(netif->radv.AdvLinkMTU);
		opt_mtu++;
	}

	/* Add prefix options */
	opt_prefix = (struct icmp_opt_prefix *) (opt_mtu);
	list = netif->radv.prefix_list;
	while (list != NULL) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("+Prefix") );

		bzero(opt_prefix, sizeof(struct icmp_opt_prefix));

		opt_prefix->type      = ICMP6_OPT_PREFIX;
		opt_prefix->len	      = 4;

		opt_prefix->flags = 0;
		if (list->AdvOnLinkFlag)      opt_prefix->flags |= ICMP6_OPT_PREF_L;
		if (list->AdvAutonomousFlag)  opt_prefix->flags |= ICMP6_OPT_PREF_A;

		opt_prefix->preflen   = (u8_t) list->PrefixLen;

		opt_prefix->valid     = htonl(list->AdvValidLifetime);
		opt_prefix->prefered  = htonl(list->AdvPreferredLifetime);

		opt_prefix->reserved  = 0;

		ip_addr_set((struct ip_addr *) &opt_prefix->prefix, &list->Prefix);

		list = list->next;
		opt_prefix++;
	}	

	/* Add Link-level source addr */
	opt_addr = (struct icmp_opt_addr *) (opt_prefix);
	if (netif->radv.AdvSourceLLAddress == TRUE) {

		LWIP_DEBUGF(IP_RADV_DEBUG, ("+LLAddr") );
		opt_addr->type = ICMP6_OPT_SRCADDR;
		opt_addr->len  = (u8_t) ((2 + netif->hwaddr_len) / 8 )	;

		memcpy(&opt_addr->addr, netif->hwaddr, netif->hwaddr_len);
	}
	LWIP_DEBUGF(IP_RADV_DEBUG, ("\n") );

	/*
	 * Send packet  
	 */
	rahdr->chksum = 0;
	rahdr->chksum = inet6_chksum_pseudo(p, &srcip, &dstip, IP_PROTO_ICMP, p->tot_len);

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tReady to send!! \n") );
	
	ICMP_STATS_INC(icmp.xmit);
	

	ip_output_if(p, &srcip, &dstip, 255, 0, IP_PROTO_ICMP , netif, &dstip, 0);

	pbuf_free(p);
}

/*  Timeouts schema:
 *
 *             
 *         last RA     DT            Min       next RA       Max
 *            |--------|---------------|----------ST-----------|--------> TIME LINE
 *
 *    Case 1: |    |---|+++|
 *            |    RS      ST      
 *            |
 *    Case 2: |               |+++|
 *            |               RS  ST  
 *            |
 *    Case 3: |                                   ST
 *            |     
 *    
 *    DT   = min_delay_RA_timeout()       (netif->MinDelayBetweenRAs)
 *    ST   = send_multicast_ra_timeout()  
 *
 *    Min  = netif->MinRtrAdvInterval 
 *    Max  = netif->MaxRtrAdvInterval
 *
 *    RS   = Router Solicitation                              
 *
 *    (1) - Solicited RS message received -> netif->solicitation_received = 1 
 *        - MinDelayBetweenRA reached -> RA will be sent after a random delay ( [0, MAX_RA_DELAY_TIME] )
 *        - RA sent
 *        
 *    (2) RS message received and RA sent after a random delay [0, MAX_RA_DELAY_TIME]
 * 
 *    (3) No RS -> Unsolicited multicast RA 
 */

void min_delay_RA_timeout(void *data);
void send_multicast_ra_timeout(void *data);

void remove_ra_timers(struct netif *netif)
{
	sys_untimeout(min_delay_RA_timeout, netif);
	sys_untimeout(send_multicast_ra_timeout, netif);
}

void ip_radv_reset_timers(struct netif *netif, int waitmax)
{
	u32_t next_send;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: reset RA timers for %c%c%d\n", __func__, netif->name[0], netif->name[1], netif->num));

	netif->radv.solicited_received   = 0;
	netif->radv.min_delay_RA_reached = 0;

	remove_ra_timers(netif);

	/* Calculate next multicast RA timeout */
	if (waitmax) {
		next_send = netif->radv.MaxRtrAdvInterval;
	}
	else
		next_send = rand_between(netif->radv.MinRtrAdvInterval, netif->radv.MaxRtrAdvInterval); 

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tNext Multicast RA at %d s (%ld ms)\n", U_INT next_send, next_send * 1000));
	sys_timeout(next_send                      * 1000, send_multicast_ra_timeout, netif);

	LWIP_DEBUGF(IP_RADV_DEBUG, ("\tMinDelayBetweenRAs = %d s (%ld ms)\n", U_INT netif->radv.MinDelayBetweenRAs, netif->radv.MinDelayBetweenRAs * 1000));
	sys_timeout(netif->radv.MinDelayBetweenRAs * 1000, min_delay_RA_timeout     , netif);
}

/* Send multicast RA and reset timers */
void send_multicast_ra(struct netif *netif)
{
	send_ra(netif, NULL);

	ip_radv_reset_timers(netif, 0);
}

/* Called when the unsolicited multicas RA have to be sent */
void send_multicast_ra_timeout(void *data)
{
	struct netif *netif = (struct netif *) data;
	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: It's time to send a multicast RA\n", __func__));

	send_multicast_ra(netif);
}

/* Called when we need to send a RA in response to a RS */
void send_multicast_ra_with_delay(struct netif *netif)
{
	u32_t delay;

	/* Router Advertisements sent in response to a Router
	   Solicitation MUST be delayed by a random time between 0 and
	   MAX_RA_DELAY_TIME seconds.
	 */

	delay = (u32_t) (MAX_RA_DELAY_TIME * rand() / (RAND_MAX + 1.0));

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: Send RA with delay %d s (%ld ms).\n ", __func__, U_INT delay, delay * 1000));

	sys_timeout(delay, send_multicast_ra_timeout, netif);
}


/* Called when the Mininum RAd interval is reached */
void min_delay_RA_timeout(void *data)
{
	struct netif *netif = (struct netif *) data;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: reached! \n", __func__));

	netif->radv.min_delay_RA_reached = 1;

	/* If we received a RS, now we must send a RA */
	if (netif->radv.solicited_received == 1) {
		send_multicast_ra_with_delay(netif);
	}
	else {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("\tNothing to do \n"));
	}
}

void remember_rs(struct netif *netif)
{
	netif->radv.solicited_received = 1;

	/* We received a solicitation, unset the next RA timeout.
	   We are going to send it at the next min_delay_RA_timeout() */
	sys_untimeout(send_multicast_ra_timeout, netif);
}
                   
void ip_radv_handle_rs(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_rs_hdr *irs)
{
	u32_t delay;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: Processing received RS \n", __func__) );

	if (irs->icode != 0) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("\tinvalide ICMP code: %d\n", (int) irs->icode));
		return;
	}

	if (IPH_HOPLIMIT(iphdr) != 255) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("\tinvalide HOP LIMIT: %d\n", (int) IPH_HOPLIMIT(iphdr)));
		return;
	}

	if (netif->radv.AdvSendAdvert == FALSE)	{
		LWIP_DEBUGF(IP_RADV_DEBUG, ("\tAdvSendAdvert is off.\n"));
		return;
	}

	/* FIX: check valid ICMP options:
	 *	- NO Link-layer Address option with unspecified IP source address! 
	 *      - others?
	 */


	if (netif->radv.UnicastOnly) {

		/* FIX: ATTENTION we stop the tcpip_thread()!!!!!! */
		sys_msleep(delay);

		send_ra(netif, &iphdr->src);
	}
	else {
		/* Have we reached the Mininum RA interval? */
		if (netif->radv.min_delay_RA_reached == 0) {
			LWIP_DEBUGF(IP_RADV_DEBUG, ("\tRS received before Mininum RA . wait!\n"));
			remember_rs(netif);
		}
		else {
			LWIP_DEBUGF(IP_RADV_DEBUG, ("\tWe can respond to the RS.\n"));
			send_multicast_ra_with_delay(netif);
		}
	}
}

/*--------------------------------------------------------------------------*/
/* Public functions */
/*--------------------------------------------------------------------------*/

void ip_radv_init(void)
{
	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: init Routing Advertising tables.\n", __func__) );

	radv_prefix_list_init();
}

void ip_radv_start(struct netif *netif)
{
	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: Routing Advertising enabled.\n", __func__) );

	if (netif->radv.AdvSendAdvert == TRUE) {

		LWIP_DEBUGF(IP_RADV_DEBUG, ("\tSending first RA\n"));

		send_ra(netif, NULL);

		ip_radv_reset_timers(netif, 1);
	}
}

void ip_radv_stop(struct netif *netif)
{
	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: Routing Advertising disabled.\n", __func__) );

	remove_ra_timers(netif);
}

void ip_radv_shutdown(struct netif *netif)
{
	netif->radv.AdvDefaultLifetime = 0;
	send_ra(netif, NULL);

	remove_ra_timers(netif);
}


int ip_radv_check_options(struct netif *netif)
{
	struct radv_prefix *prefix;
	int res = 1;	

	if ((netif->radv.MinRtrAdvInterval < MIN_MinRtrAdvInterval) || 
		    (netif->radv.MinRtrAdvInterval > MAX_MinRtrAdvInterval(netif)))
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, ( 
		//	"MinRtrAdvInterval (%.2f) must be at least %.2f but no more than 3/4 of MaxRtrAdvInterval (%.2f)",
		//	netif->radv.MinRtrAdvInterval,
		//	(int)MIN_MinRtrAdvInterval,
		//	MAX_MinRtrAdvInterval(netif)));

		res = -1;
	}

	if ((netif->radv.MaxRtrAdvInterval < MIN_MaxRtrAdvInterval) 
			|| (netif->radv.MaxRtrAdvInterval > MAX_MaxRtrAdvInterval))
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, (
		//	"MaxRtrAdvInterval (%.2f) must be between %.2f and %d",
		//	netif->radv.MaxRtrAdvInterval,
		//	(int)MIN_MaxRtrAdvInterval,
		//	MAX_MaxRtrAdvInterval));
		res = -1;
	}

	if (netif->radv.MinDelayBetweenRAs < MIN_DELAY_BETWEEN_RAS) 
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, (
		//	"MinDelayBetweenRAs (%.2f) must be at least %.2f",
		//	netif->radv.MinDelayBetweenRAs,
		//	MIN_DELAY_BETWEEN_RAS));
		res = -1;
	}

	if ( (netif->radv.AdvLinkMTU != 0) &&
	     ((netif->radv.AdvLinkMTU < MIN_AdvLinkMTU) || (netif->radv.AdvLinkMTU > netif->mtu))
	   )
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, ("AdvLinkMTU for %s (%u) must be zero or between %u and %u",
		//netif->radv.AdvLinkMTU, MIN_AdvLinkMTU, netif->mtu));
		res = -1;
	}

	if (netif->radv.AdvReachableTime >  MAX_AdvReachableTime)
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, (
		//	"AdvReachableTime for %s (%u) must not be greater than %u",
		//	netif->radv.AdvReachableTime, MAX_AdvReachableTime));
		res = -1;
	}

	if (netif->radv.AdvCurHopLimit > MAX_AdvCurHopLimit)  /* FIX: always true due to limited range of data type */
	{                                                                            
		//LWIP_DEBUGF(IP_RADV_DEBUG, ("AdvCurHopLimit for %s (%u) must not be greater than %u",
		//	netif->radv.AdvCurHopLimit, MAX_AdvCurHopLimit));
		res = -1;
	}
	
	if ((netif->radv.AdvDefaultLifetime != 0) &&
	    ((netif->radv.AdvDefaultLifetime > MAX_AdvDefaultLifetime) ||
	     (netif->radv.AdvDefaultLifetime < MIN_AdvDefaultLifetime(netif))))
	{
		//LWIP_DEBUGF(IP_RADV_DEBUG, ( 
		//	"AdvDefaultLifetime for %s (%u) must be zero or between %u and %u",
		//	netif->radv.AdvDefaultLifetime, MIN_AdvDefaultLifetime(iface),
		//	MAX_AdvDefaultLifetime));
		res = -1;
	}

	/* XXX: need this? prefix = netif->radv.AdvPrefixList; */
	prefix =  netif->radv.prefix_list;
	while (prefix)
	{
		if (prefix->PrefixLen > MAX_PrefixLen)
		{
			//LWIP_DEBUGF(IP_RADV_DEBUG, ("invalid prefix length (%u)", prefix->PrefixLen));
			res = -1;
		}

		if (prefix->AdvPreferredLifetime > prefix->AdvValidLifetime)
		{
			//LWIP_DEBUGF(IP_RADV_DEBUG, ("AdvValidLifetime (%u) must be greater than AdvPreferredLifetime for", 
			//	prefix->AdvValidLifetime));
			res = -1;
		}

		prefix = prefix->next;
	}



	if (res <= 0) {
		LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: RA disabled on '%c%c%d'.\n", __func__, netif->name[0], netif->name[1], netif->num) );
		netif->radv.AdvSendAdvert = FALSE;
	}

	return res;
}


#endif   /* IPv6_ROUTER_ADVERTISEMENT */































































#if 0

#define DATA_POOL_SIZE   10

static struct radv    data_pool[DATA_POOL_SIZE];
static struct radv   *data_freelist;

void radv_data_list_init(void)
{
	register int i;
	for (i=0; i<DATA_POOL_SIZE-1; i++)
		data_pool[i].next = data_pool + ( i + 1);

	data_pool[i].next = NULL;
	data_freelist     = data_pool;
}

void ip_radv_data_init(struct radv *rinfo);

struct radv *radv_data_list_alloc()
{
	struct radv *el;

	if (data_freelist == NULL)
		return NULL;
	else {
		el = data_freelist;
		data_freelist = data_freelist->next;

		ip_radv_data_init(el);

		return el;
	}
}

void radv_data_list_free(struct radv *el)
{
	el->next        = data_freelist;
	data_freelist = el;
}


/*--------------------------------------------------------------------------*/

#endif

