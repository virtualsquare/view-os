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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */ 

#if IPv6_AUTO_CONFIGURATION

#ifndef __LWIP_IP_AUTOCONF_H__
#define __LWIP_IP_AUTOCONF_H__

/*--------------------------------------------------------------------------*/
/* Protocol Costants (RFC 2461) */
/*--------------------------------------------------------------------------*/

#define UNSPECIFIED                  0

#define INFINITE_LIFETIME            0xffffffff

#define RETRANS_TIMER			     1000 /* milliseconds */

/* Host constants: */
#define MAX_RTR_SOLICITATION_DELAY	 1 /* seconds */
#define RTR_SOLICITATION_INTERVAL	 4 /* seconds */
#define MAX_RTR_SOLICITATIONS		 3 /* transmissions */


/*--------------------------------------------------------------------------*/
/* Per-interface data used by stateless autoconfiguration protocol. */
/*--------------------------------------------------------------------------*/

struct netif;
struct ip_addr;

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
#define DUP_ADDR_DETECT_TRANSMITS  1

	/* RetransTimer. Milliseconds between retransmitted 
	   Neighbor Solicitation messages. Default: RETRANS_TIMER. */
    u32_t retrans_timer;

	/* Number of sent RS */
	u8_t  rtr_sol_counter;            

	/* Initial delay befor first solicitation in seconds. 
	   Default: MAX_RTR_SOLICITATION_DELAY */
	u16_t max_rtr_solicitation_delay;  

	/* Interval between solicitations in seconds.
	   Default: RTR_SOLICITATION_INTERVAL */
	u16_t rtr_solicitation_interval;  

	/* Max Number of solicitations.
	   Default: MAX_RTR_SOLICITATIONS */
	u8_t  max_rtr_solicitations;      
};


/*--------------------------------------------------------------------------*/
/* Per-address informations */
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

/*--------------------------------------------------------------------------*/
/* Module Functions and costants */
/*--------------------------------------------------------------------------*/

/* Autoconfiguration Timer timeout (1 second) */
#define AUTOCONF_TMR_INTERVAL    1000 

/* Called by ip_init() */
void ip_autoconf_init(struct stack *stack);
void ip_autoconf_shutdown(struct stack *stack);


/* Called by netif_add() */
void ip_autoconf_netif_init(struct netif *netif);

/* Called by ip_change() */
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

