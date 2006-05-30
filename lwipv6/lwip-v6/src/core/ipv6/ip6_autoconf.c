/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Diego Billi - Italy
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
#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"

#include "lwip/icmp.h"
#include "lwip/ip_autoconf.h"

#include "lwip/netlinkdefs.h"


#ifdef IPv6_AUTO_CONFIGURATION

#define INLINE   __inline__

#ifndef IP_AUTOCONF_DEBUG
#define IP_AUTOCONF_DEBUG     DBG_OFF
#endif

void dad_timeout(void *arg);
void dad_remove_timer(struct ip_addr_list *addr);
void start_dad_on_addr(struct ip_addr_list *addr, struct netif *netif);

/*--------------------------------------------------------------------------*/
/* Global variabiles */
/*--------------------------------------------------------------------------*/

/* Global default value for DupAddrDetectTransmits */
u8_t dad_duptrans_default = 1;
/* Global default value for DupAddrDetectTransmits */
u32_t dad_retrans_delay_default = 1000; /* milliseconds */

/* Global default values for Router solicitations */
u8_t  max_rtr_solicitations_default      = 3;     
u16_t rtr_solicitation_interval_default  = 2000;  /* milliseconds */
u16_t max_rtr_solicitation_delay_default = 500;  /* milliseconds */


/*--------------------------------------------------------------------------*/
/* Functions */
/*--------------------------------------------------------------------------*/

void ip_autoconf_init(void)
{
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: IPv6 Address Autoconfiguration Enabled.\n", __func__));	
}

/* Initialize interface data for autoconfiguration protocol */
void ip_autoconf_netif_init(struct netif *netif)
{
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: Init interface %c%c%d.\n", __func__, netif->name[0],netif->name[1],netif->num));

	netif->autoconf.status = AUTOCONF_INIT;

	netif->autoconf.flag_M = 0; 
	netif->autoconf.flag_O = 0;

	netif->autoconf.dad_duptrans = dad_duptrans_default; 
        netif->autoconf.dad_retrans_delay = dad_retrans_delay_default;  /* milliseconds */

	netif->autoconf.rtr_sol_counter = 0;
	netif->autoconf.max_rtr_solicitations      = max_rtr_solicitations_default;
	netif->autoconf.rtr_solicitation_interval  = rtr_solicitation_interval_default;
	netif->autoconf.max_rtr_solicitation_delay = max_rtr_solicitation_delay_default;


	netif->autoconf.addrs_tentative = NULL;
}


int create_address_from_prefix(struct ip_addr *ip, struct ip_addr *netmask, 
	struct ip_addr *prefix, int prefixlen, struct netif *netif)
{
	/* FIX FIX FIX FIX: very bad way to create address XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*/
	IP6_ADDR_LINKSCOPE(ip, netif->hwaddr);

	memcpy(ip, prefix, prefixlen / 8);

	SET_ADDR_MASK((char*)netmask, prefixlen);

	return 1;
}


/* 
 * TODO: read better: RFC 2461 - 6.3.4. Processing Received Router Advertisements 
 */
void ip_autoconf_handle_ra(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_ra_hdr *ira)
{
	u16_t  icmp_len;
	struct icmp_opt        *opt;
	struct icmp_opt_addr   *oaddr = NULL;
	struct icmp_opt_prefix *oprefix = NULL;
	struct icmp_opt_mtu    *omtu = NULL;

	struct ip_addr prefix;
	struct ip_addr ipaddr;
	struct ip_addr netmask;
	struct ip_addr_list *confaddr;

	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: Processing received RA \n", __func__) );

	if (ira->icode != 0) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: invalide ICMP code: %d",__func__, ira->icode));
		return;
	}

	if (IPH_HOPLIMIT(iphdr) != 255) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: invalide HOP LIMIT: %d", __func__, IPH_HOPLIMIT(iphdr)));
		return;
	}


	/* Scan for options */
	icmp_len = sizeof(struct icmp_ra_hdr);
	while (p->tot_len > icmp_len) {
		opt = (struct icmp_opt *) (p->payload + icmp_len);
		switch (opt->type) {
			case ICMP6_OPT_SRCADDR:  /* Found SourceAdd option */
				oaddr = (struct icmp_opt_addr *) opt;
				break;		
			case ICMP6_OPT_PREFIX:  /* Found Prefix option */
				oprefix = (struct icmp_opt_prefix *) opt;
				break;
			case ICMP6_OPT_MTU:  /* Fount Link MTU Option */
				omtu = (struct icmp_opt_mtu *) opt;
				break;
			default:
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tICMP: *** BUG (unknow type %d)***. SKIP\n", opt->type) );
				break;
		}
		icmp_len += opt->len * 8; 
	}

	/* Handle router informations */

	/* if Lifetime == 0 the router is not a default router and 
	   SHOULD NOT appear on the default router list. */
	if (ira->life != 0) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tThis is default router: "));
		ip_addr_debug_print(IP_AUTOCONF_DEBUG, &iphdr->src); 
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));

		/* TODO: check if the entry already exists and implement route lifetime */
                IP6_ADDR_UNSPECIFIED(&ipaddr);
                IP6_ADDR_UNSPECIFIED(&netmask);
		ip_route_list_add(&ipaddr,&netmask, &iphdr->src, netif, 0);
	}

	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tHop-Lim:%u ", ira->hoplimit));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("[M:%d O:%u] " , (ira->m_o_flag & ICMP6_RA_M)?1:0 , (ira->m_o_flag & ICMP6_RA_O)?1:0 ));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("Life:%d "     , ntohs(ira->life)   ));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("Reach:%d "    , (unsigned int)ntohl(ira->reach)  ));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("Retrans:%u\n" , (unsigned int)ntohl(ira->retran) ));

	if (ira->hoplimit != 0) {
		/* TODO: up to now, HOPLIMIT values for TCP/UPD/ICMP are fixed
		         (TCP_TTL, UDP_TTL, ICMP_TTL). :-/ */
	}

	if (ira->m_o_flag & ICMP6_RA_M) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("Statefull or Stateless+DHCP configuration not supported!\n"));
		/* TODO */
		return;
	}

	if (ira->reach != 0) {
		/* TODO: reachability detection non implemented yet */
	}

	if (ira->retran != 0) {
		netif->autoconf.dad_retrans_delay = ntohl(ira->retran);
	}

	/* Handle options */

	if (oaddr != NULL) {

		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tSrcAddr: %02x:%02x:%02x:%02x:%02x:%02x (len=%d)\n",  
			oaddr->addr[0],oaddr->addr[1],oaddr->addr[2],
			oaddr->addr[3],oaddr->addr[4],oaddr->addr[5], oaddr->len * 8));

		/* TODO: update or refresh ARP table */
	}

	if (omtu != NULL) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tLink MTU: %u (len=%u)\n", (unsigned int) ntohl(omtu->mtu), omtu->len * 8));
		/* TODO: update Link MTU */
		netif->mtu = ntohl(omtu->mtu);
	}

        if (oprefix != NULL) {
		/* Save prefix */
		memcpy(&prefix, &oprefix->prefix, sizeof(struct ip_addr) );

		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tPrefix: ")); ip_addr_debug_print(IP_AUTOCONF_DEBUG, &prefix); LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("/%d  ", oprefix->preflen));
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("[L:%d A:%d] Valid=%u Prefered=%u\n", 
			(oprefix->flags & ICMP6_OPT_PREF_L)?1:0, 
			(oprefix->flags & ICMP6_OPT_PREF_A)?1:0, 
			(unsigned int) ntohl(oprefix->valid), 
			(unsigned int) ntohl(oprefix->prefered)));

		/* We can use this prefix for autoconfiguration */
		if (oprefix->flags & ICMP6_OPT_PREF_A) {

			confaddr = ip_addr_list_alloc();
			if (confaddr != NULL) {

				confaddr->flags = IFA_F_TENTATIVE;
		
				confaddr->netif = netif;

				//FIX FIX: prefered time is relative to the prefix!
				confaddr->info.prefered = ntohl(oprefix->prefered);
				confaddr->info.valid    = ntohl(oprefix->valid);

				create_address_from_prefix(&confaddr->ipaddr, &confaddr->netmask, &prefix, oprefix->preflen, netif);

				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tNetif IP: ")); ip_addr_debug_print(IP_AUTOCONF_DEBUG, &confaddr->ipaddr); LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tNetmask : ")); ip_addr_debug_print(IP_AUTOCONF_DEBUG, &confaddr->netmask); LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));

				/* This is a new autogenerated address ? */
				if (ip_addr_list_find(netif->addrs, &confaddr->ipaddr, &confaddr->netmask) == NULL) {

					/* Add address to interface */
					LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tAdding configured address...\n"));
			
					/* Store it in tentative addresses */
					ip_addr_list_add(&(netif->autoconf.addrs_tentative), confaddr);
			
					/* this prefix can be used for on-link determination. */
					if (oprefix->flags & ICMP6_OPT_PREF_L) {
						/* Add routing rule to reach onlink */
						LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tAdding routing informations...\n"));

						ip_addr_set(&ipaddr, &(confaddr->ipaddr));
						ip_addr_set(&netmask, &(confaddr->netmask));

						ip_route_list_add(&ipaddr, &netmask, NULL, netif, 0);
					}
			
					netif->autoconf.status = AUTOCONF_SUCC;
			
					/* Start DAD on new address */
					start_dad_on_addr(confaddr, netif);
				}
				else {
					/* Discard autogenerated packet */
					LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tAddress already added.\n"));
					ip_addr_list_free(confaddr);

                               		/* TODO: update (address|route entry)'s life-time information? */
				}

			}
			else {
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("*** NO MORE MEMORY FOR ADDRESS!***\n"));
			}
		}
	}
}

void ip_autoconf_handle_na(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_na_hdr *ina) 
{
	struct ip_addr_list * ip;

	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: Processing received NA \n", __func__) );


	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: [S=%d,R=%d,O=%d] ", __func__,
		ina->rso_flags & ICMP6_NA_S,
		ina->rso_flags & ICMP6_NA_R,
		ina->rso_flags & ICMP6_NA_O) );
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tTarget IP: ")); ip_addr_debug_print(IP_AUTOCONF_DEBUG, (struct ip_addr *) &ina->targetip); LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));

	/* Is this a response to a Neighbor Solicitation from the Destination address? */
	if (ina->rso_flags & ICMP6_NA_S) {

		/* If this advertisment is a response to a DAD message, 
		   the IP source address have to be a all-nodes multicast address. */

		if (ip_addr_isallnode(&iphdr->dest)) {

			LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tMaybe a DAD response for us.\n") );

			/* Check for tentative addresses! */	
			ip = ip_addr_list_maskfind(netif->autoconf.addrs_tentative, (struct ip_addr *) &ina->targetip);
			if (ip != NULL) {

				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tAddress found!\n"));
				if (ip->info.flag == IPADDR_TENTATIVE) {

					LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\tIs TENTATIVE, remove it!\n"));

                                        /* Remove DAD timeout */
					dad_remove_timer(ip);

					/* This address is duplicated, remove it */
					ip_addr_list_del(&netif->autoconf.addrs_tentative, ip);
					ip_addr_list_free(ip);

					/* FIX: remove any routing table's entries ???? */

					/* If address was Link-local, disable interface */
					if (ip_addr_islinkscope(&ip->ipaddr)) {

						netif->autoconf.status = AUTOCONF_FAIL;
						//netif->flags &= ~NETIF_FLAG_UP;
						netif_set_down(netif);
					}
				}
			}
			else {
                        	/* what to do? */
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("*** Received NS, but we don't have tentative addresses!\n"));
			}
		}
		else {
			/* TODO: simple NS*/
		}
	}
	else {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("*** Received NS, but not solicited!\n"));
		/* TODO: */
	}

	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: stop \n", __func__) );

}

/*--------------------------------------------------------------------------*/
/* Duplicate Address Detection (DAD) functions */
/*--------------------------------------------------------------------------*/

void dad_timeout(void *arg)
{
	struct ip_addr_list *addr = (struct ip_addr_list *) arg;
	struct netif * netif = addr->netif;

	/* FIX: LOCK netif->addr */

	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: start on ", __func__));                        
	ip_addr_debug_print(IP_AUTOCONF_DEBUG, &(addr->ipaddr));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));                        

        /* If address still is TENTATIVE */
	if (addr->info.flag == IPADDR_TENTATIVE) {
		/* More probes to send? */
		if (addr->info.dad_counter < addr->netif->autoconf.dad_duptrans) {
			LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: still TENTATIVE (probes %d/%d)\n", __func__, addr->info.dad_counter, addr->netif->autoconf.dad_duptrans));  
			icmp_send_dad(addr, netif);
			addr->info.dad_counter++;
			/* Set next timeout */
			sys_timeout(netif->autoconf.dad_retrans_delay, (sys_timeout_handler)dad_timeout, addr);
		}
		else {
			LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: now PERMANENT\n", __func__));                        
			addr->flags = IFA_F_PERMANENT;
			addr->info.flag = IPADDR_PREFERRED;

			/* Move from tenative to permanent */
			ip_addr_list_del(&netif->autoconf.addrs_tentative, addr);

			/* FIX FIX: LOCK netif->addrs */
			ip_addr_list_add(&netif->addrs, addr);
			/* FIX FIX: UNLOCK netif->addrs */
		}
	}

	/* FIX: UNLOCK netif->addr */
}

void dad_remove_timer(struct ip_addr_list *addr)
{
	sys_untimeout((sys_timeout_handler)dad_timeout, addr);
}

/* Start Duplicate Address Detection in the address "addr" */
void start_dad_on_addr(struct ip_addr_list *addr, struct netif *netif)
{
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: start on ", __func__));                        
	ip_addr_debug_print(IP_AUTOCONF_DEBUG, &(addr->ipaddr));
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));                        

	addr->flags = IFA_F_TENTATIVE;
	addr->info.flag = IPADDR_TENTATIVE;
	addr->info.dad_counter = 0;

	icmp_send_dad(addr, netif);

	/* Set DAD timeout for this entry. */
	addr->info.dad_counter++;
	sys_timeout(netif->autoconf.dad_retrans_delay, (sys_timeout_handler)dad_timeout, addr);
}



/*--------------------------------------------------------------------------*/
/* Router Solicitation functions */
/*--------------------------------------------------------------------------*/

/* 
 * See RFC 2461: 6.3.7.  Sending Router Solicitations 
 */
void rtr_sol_timeout(void *arg)
{
	struct netif *netif = (struct netif *) arg;
	struct ip_addr_list unspecified;
	struct ip_addr      linkscope;
	struct ip_addr_list *srcaddr;

	/* If we received a Router Advertisment then netif->autoconf.status != INIT and
	   stop protocol */
	if (netif->autoconf.status != AUTOCONF_INIT) 
		return;

	/* More probe to send? */
	if (netif->autoconf.rtr_sol_counter < netif->autoconf.max_rtr_solicitations) {

		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: sending RS (%d/%d).\n", __func__, netif->autoconf.rtr_sol_counter, netif->autoconf.max_rtr_solicitations));                        

		/* Have we got a valid (not tentative) link-scope address? */
		IP6_ADDR_LINKSCOPE(&linkscope, netif->hwaddr);
		srcaddr = ip_addr_list_maskfind(netif->addrs, &linkscope);
		if (srcaddr == NULL) {
			/* If we don't have link-scope address yet, use unspecified address */
			IP6_ADDR_UNSPECIFIED(&(unspecified.ipaddr));
			unspecified.netif = netif;		
			srcaddr = &unspecified;
		}

		/* Send RS */
		icmp_router_solicitation(NULL, srcaddr);
		netif->autoconf.rtr_sol_counter++;

                /* Set next timeout */
		sys_timeout( netif->autoconf.rtr_solicitation_interval, (sys_timeout_handler)rtr_sol_timeout, netif);
	}
	else {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: no routers on the link.\n", __func__));                        
		netif->autoconf.status = AUTOCONF_FAIL;
	}
}

/* Start Duplicate Address Detection in the address "addr" */
void start_router_solicitation(struct netif *netif)
{
	unsigned int r;
	u32_t delay;

	/* Before a host sends an initial solicitation, it SHOULD delay the
	   transmission for a random amount of time between 0 and
	   MAX_RTR_SOLICITATION_DELAY */
	delay = ( ((float)rand_r(&r)) / RAND_MAX ) * netif->autoconf.max_rtr_solicitation_delay  ;
	LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: start initial delay (%d/%d).\n", __func__, (unsigned int) delay, 
		(int) netif->autoconf.max_rtr_solicitation_delay));

	netif->autoconf.rtr_sol_counter = 0;

	sys_timeout(delay, (sys_timeout_handler)rtr_sol_timeout, netif);
}

/*--------------------------------------------------------------------------*/
/* Autoconfiguration timer */
/*--------------------------------------------------------------------------*/

/* Update lifetime and returns 1 if there is a valid (or tentative) link-scope 
   address in the list */
INLINE static int addr_update_lifetime(struct ip_addr_list **addrs, u32_t time)
{
	struct ip_addr_list *cur, *next;
	struct ip_addr_list *list, *new_list;
	int r = 0;
	
	if (*addrs == NULL) 
		return 0;

	/* 
	 * Save in "new_list" the valid addresses and free the others. 
	 */

	/* FIX: LOCK addrs */
	list = *addrs;
	new_list = NULL;

	cur = list;
	do {
		next = cur->next;

		/* Skip IPV4 and not autoconfigured!!! */
		if (cur->info.flag == IPADDR_NONE) {
			ip_addr_list_add(&new_list, cur);
		}
		else {
			/* Update address lifetime */
			if (cur->info.prefered != INFINITE_LIFETIME)
				cur->info.prefered -= time; 
			if (cur->info.valid != INFINITE_LIFETIME)
				cur->info.valid -= time; 

			/* Update address status */
			if (cur->info.flag & IPADDR_VALID) {
				if (cur->info.prefered == 0) {
					cur->info.flag = IPADDR_DEPRECATED;
					cur->flags     = IFA_F_DEPRECATED;
				}
				if (cur->info.valid == 0) 
					cur->info.flag = IPADDR_INVALID;
			}

			if (cur->info.flag != IPADDR_INVALID) {
				ip_addr_list_add(&new_list, cur);
				r = 1;
			}
			else {
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: address expired! ", __func__));                        
				ip_addr_debug_print(IP_AUTOCONF_DEBUG, &(cur->ipaddr));
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));                        
				/* TODO: Remove this address, close connections, ecc... */
				ip_addr_list_free(cur);
			}
		}

		cur = next;
	} while (cur != list);

	*addrs = new_list;

	/* FIX: UNLOCK addrs */

	return r;
}

static struct ip_addr_list * create_link_scope_addr(struct netif *netif)
{
	struct ip_addr_list *add = NULL;
	
	add = ip_addr_list_alloc();
	if (add != NULL) {

		IP6_ADDR_LINKSCOPE(&(add->ipaddr), netif->hwaddr);
		IP6_ADDR(&(add->netmask), 0xffff,0xffff,0xffff,0xffff,0x0,0x0,0x0,0x0);
		add->netif = netif;
		add->flags = IFA_F_TENTATIVE;

		/* Now add Autoconfigurations info */
		add->info.flag = IPADDR_TENTATIVE;
		add->info.dad_counter = 0;

		/* A link-local address has an infinite preferred and 
   		   valid lifetime; it is never timed out. */
		add->info.prefered = INFINITE_LIFETIME;
		add->info.valid    = INFINITE_LIFETIME;
	}

	return add;
}


static void remove_autoconf_data(struct netif *netif)
{
	struct ip_addr_list *cur, *next;
	struct ip_addr_list *list, *new_list;

	/* FIX: UNLOCK netif->addr */


	/* Remove assigned addresses */	
	if (netif->addrs != NULL) {
		/* Save in "new_list" the valid addresses and free the others. */
		list = netif->addrs;
		new_list = NULL;

		cur = list;
		do {
			next = cur->next;
	
			/* Skip IPV4 and not autoconfigured IPV6 !!! */
			if (cur->info.flag == IPADDR_NONE) {
				ip_addr_list_add(&new_list, cur);
			}
			else {
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: removing: ", __func__));                        
				ip_addr_debug_print(IP_AUTOCONF_DEBUG, &(cur->ipaddr));
				LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));                        
	
				/* ABORT TCP,UDP,ICMP connections */
				//ip_addr_close(&(cur->ipaddr));

				ip_addr_list_free(cur);
			}
	
			cur = next;
		} while (cur != list);
	
		netif->addrs = new_list;
	}

	/* FIX: UNLOCK netif->addr */

	/* Remove tentative addresses */
	while (netif->autoconf.addrs_tentative != NULL) {
		cur = ip_addr_list_first(netif->autoconf.addrs_tentative);

		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: tentative removing: ", __func__));                        
		ip_addr_debug_print(IP_AUTOCONF_DEBUG, &(cur->ipaddr));
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("\n"));                        

		dad_remove_timer(cur);

		ip_addr_list_del(&(netif->autoconf.addrs_tentative), cur);
	}

	/* 
	 * FIX: REMOVE ROUTING TABLE ENTRIES 
	 */
}

/*--------------------------------------------------------------------------*/

void ip_autoconf_timer(void *arg)
{
	int have_linkaddr = 0;

	struct netif *netif = (struct netif *) arg;

	//LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: start on %c%c%d \n", __func__,	
	//	netif->name[0], netif->name[1], netif->num));

	/* Update addresses status (and remove invalid addresses) */
	have_linkaddr =  addr_update_lifetime(&netif->autoconf.addrs_tentative, (AUTOCONF_TMR_INTERVAL/1000));

	/* FIX: LOCK netif->addrs */
	have_linkaddr |= addr_update_lifetime(&netif->addrs, (AUTOCONF_TMR_INTERVAL/1000));
	/* FIX: UNLOCK netif->addrs */

	sys_timeout(AUTOCONF_TMR_INTERVAL, ip_autoconf_timer  , netif);
}

void ip_autoconf_start(struct netif *netif)
{
	struct ip_addr_list *linkadd;

	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: start.\n", __func__) );


	/* If autoconfiguration has not started yet */
	if (netif->autoconf.status == AUTOCONF_INIT) {


		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: creating link-scope address.\n", __func__));                        

		linkadd = create_link_scope_addr(netif);
		if (linkadd != NULL) {
			/* Add link-scope address as tentative */
			ip_addr_list_add(&(netif->autoconf.addrs_tentative),linkadd);

			/* Add routing entry for link-scope addresses */
			ip_route_list_add(&(linkadd->ipaddr),&(linkadd->netmask), NULL, netif, 0);

			/* Start DAD on link-scope address */
			start_dad_on_addr(linkadd, netif);

			sys_timeout(AUTOCONF_TMR_INTERVAL, ip_autoconf_timer  , netif);

		}
		else {
			LWIP_DEBUGF( IP_AUTOCONF_DEBUG, ("%s: unable to create link-scop address. No more memory.\n", __func__) );

			/* Disable interface */
			//netif->flags &= ~NETIF_FLAG_UP;
			ip_change(netif, NETIF_CHANGE_DOWN);
			netif_set_down_low(netif);

			netif->autoconf.status = AUTOCONF_FAIL;
		}

		/* Router solicitation starts concurrently with Autoconfiguration to save time. */
		start_router_solicitation(netif);
	} 
}

void ip_autoconf_stop(struct netif *netif)
{
	LWIP_DEBUGF(IP_RADV_DEBUG, ("%s: start.\n", __func__) );

	if (netif->autoconf.status != AUTOCONF_INIT) {
		LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: %c%c%d set down. reset data\n", __func__, netif->name[0],netif->name[1],netif->num));                        
		remove_autoconf_data(netif);
		netif->autoconf.status = AUTOCONF_INIT;
	}

	sys_untimeout(ip_autoconf_timer, netif);
}

/*--------------------------------------------------------------------------*/


#endif


#if 0
/* Update interface status and check life-fime of every addresses.
 * Called every second
 */
void ip_autoconf_tmr(struct netif *netif)
{
	struct ip_addr_list *linkadd;
	int have_linkaddr = 0;

	/*
	 * FIX: check interface's status UP or DOWN every second, it's too long interval.
	 */

	/* The interface is down? */
	if ( (netif->flags & NETIF_FLAG_UP) != NETIF_FLAG_UP) {
		/* If the interface is down but autoconfiguration was started 
		   then reset all data */
		if (netif->autoconf.status != AUTOCONF_INIT) {
			LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: %c%c%d set down. reset data\n", __func__, netif->name[0],netif->name[1],netif->num));                        

			remove_autoconf_data(netif);

			netif->autoconf.status = AUTOCONF_INIT;
		}
		return;
	}

	/* Update addresses status (and remove invalid addresses) */
	have_linkaddr =  addr_update_lifetime(&netif->autoconf.addrs_tentative, (AUTOCONF_TMR_INTERVAL/1000));

	/* FIX: LOCK netif->addrs */
	have_linkaddr |= addr_update_lifetime(&netif->addrs, (AUTOCONF_TMR_INTERVAL/1000));
	/* FIX: UNLOCK netif->addrs */

	/* If autoconfiguration has not started yet */
	if (netif->autoconf.status == AUTOCONF_INIT) {

		/* Haven't got Link-scope address? (Neither VALID nor TENTATIVE) */
		if (have_linkaddr == 0) {

			LWIP_DEBUGF(IP_AUTOCONF_DEBUG, ("%s: creating link-scope address.\n", __func__));                        

			linkadd = create_link_scope_addr(netif);
			if (linkadd != NULL) {
				/* Add link-scope address as tentative */
				ip_addr_list_add(&(netif->autoconf.addrs_tentative),linkadd);

				/* Add routing entry for link-scope addresses */
				ip_route_list_add(&(linkadd->ipaddr),&(linkadd->netmask), NULL, netif, 0);

				/* Start DAD on link-scope address */
				start_dad_on_addr(linkadd, netif);
			}
			else {
				LWIP_DEBUGF( IP_AUTOCONF_DEBUG, ("%s: unable to create link-scop address. No more memory.\n", __func__) );

				/* Disable interface */
				//netif->flags &= ~NETIF_FLAG_UP;

				ip_change(netif, NETIF_CHANGE_DOWN);
				netif_set_down_low(netif);

				netif->autoconf.status = AUTOCONF_FAIL;
			}

			/* Router solicitation starts concurrently with 
			   autoconfiguration to save time. */
			start_router_solicitation(netif);
		}
	} 
}
#endif


