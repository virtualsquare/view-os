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

#ifdef IPv6_AUTO_CONFIGURATION

#ifndef __LWIP_IP_AUTOCONF_H__
#define __LWIP_IP_AUTOCONF_H__

struct netif;
struct ip_addr;

/*
 * Per-interface data used by stateless autoconfiguration protocol.
 */
struct autoconf {
	
	/* Autoconfiguration protocol status */
	u8_t status;
#define AUTOCONF_INIT 0x00  
#define AUTOCONF_FAIL 0x01
#define AUTOCONF_SUCC 0x02   

	u8_t flag_M;
	u8_t flag_O;

	/* List of tentative addresses.
	   A tentative address is not considered "assigned to an
	   interface" in the traditional sense. That is, the interface must
	   accept Neighbor Solicitation and Advertisement messages containing
	   the tentative address in the Target Address field.
        */
	struct ip_addr_list * addrs_tentative;

	/* DupAddrDetectTransmits
	   The number of consecutive Neighbor Solicitation
	   messages sent while performing Duplicate Address
	   Detection on a tentative address [rfc2462]. */
	u8_t dad_duptrans; 

	/* Retrans Timer
	   The time, in milliseconds, between retransmitted 
	   Neighbor Solicitation messages. Set by Router 
	   Advertisement message [rfc2461]*/
        u32_t dad_retrans_delay;  /* milliseconds */

	u8_t  rtr_sol_counter;            /* Number of sent RS */
	u8_t  max_rtr_solicitations;      /* Number of solicitations */
	u16_t rtr_solicitation_interval;  /* Interval between solicitations */
	u16_t max_rtr_solicitation_delay; /* Initial delay befor first solicitation */
};

/* Global default values for DupAddrDetectTransmits */
extern u8_t dad_duptrans_default;

/* Global default values for DupAddrDetectTransmits */
extern u32_t dad_retrans_delay_default; /* milliseconds */

/* Global default values for Router solicitations */
extern u8_t max_rtr_solicitations_default;     
extern u16_t rtr_solicitation_interval_default;   /* seconds */
extern u16_t max_rtr_solicitation_delay_default;


/*--------------------------------------------------------------------------*/

/*
 *  Autoconfigured Address States
 *
 *                |<----------Valid ---------->|
 *  |  Tentative  |  Preferred  |  Deprecated  |  Invalid
 *  |==========================================================> TIME
 *  |<-- Preferred Lifetime --->|              |
 *  |<----------- Valid Lifetime ------------->|
 */

#define  IPADDR_NONE         0x00
/* IPADDR_TENTATIVE addresses aren't stored in net->addr */
#define  IPADDR_TENTATIVE    0x01
#define  IPADDR_VALID        0x02
#define  IPADDR_PREFERRED    0x12
#define  IPADDR_DEPRECATED   0x22
#define  IPADDR_INVALID      0x04

/*
 * FIX: Netlink code defines IFA_F_DEPRECATED, IFA_F_TENTATIVE, IFA_F_PERMANENT
 *      for the ip_addr_list::flag field. We set both IFA_F_* and IPADDR_*
 *      during autoconfiguration. Find a way to use only one of them.
 */

struct addr_info {
	u8_t  flag;
	u8_t  dad_counter;     /* number of tentatives for DAD protocol */

	/* Life-time */
	u32_t prefered;
	u32_t valid;
};

#define INFINITE_LIFETIME   0xffffffff

/*--------------------------------------------------------------------------*/
/* Functions */
/*--------------------------------------------------------------------------*/

/* Called by ip_init() */
void ip_autoconf_init(void);

/* Called by netif_add() */
void ip_autoconf_netif_init(struct netif *netif);

#define AUTOCONF_TMR_INTERVAL  1000 
void ip_autoconf_tmr(struct netif *netif);



void ip_autoconf_start(struct netif *netif);
void ip_autoconf_stop(struct netif *netif);




struct ip_hdr;
struct icmp_ra_hdr;
struct icmp_na_hdr;
struct pbuf;

/* Called by ICMP level when Router Advertisment messages are received */
void ip_autoconf_handle_ra(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_ra_hdr *ira);

/* Called by ICMP level when Neighbor Advertisment messages are received */
void ip_autoconf_handle_na(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_na_hdr *ina);


#endif /* LWIP_IP_AUTOCONF */

#endif /* IPv6_AUTO_CONFIGURATION */

