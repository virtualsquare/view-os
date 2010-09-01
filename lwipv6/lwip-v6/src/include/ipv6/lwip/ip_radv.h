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

#if IPv6_ROUTER_ADVERTISEMENT

/* FIX: add MULTISTACK support */

#ifndef __LWIP_IP_RADV_H__
#define __LWIP_IP_RADV_H__


/*--------------------------------------------------------------------------*/
/* Costants */
/*--------------------------------------------------------------------------*/
#ifndef UNSPECIFIED
#define UNSPECIFIED	0
#endif

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif

#define RADV_MAX(X,Y)   (((X)>=(Y)) ? (X) : (Y))

/*--------------------------------------------------------------------------*/
/* Protocol Costants */
/*--------------------------------------------------------------------------*/

/* Router constants: */

#define MAX_INITIAL_RTR_ADVERT_INTERVAL	16           /* seconds */
#define MAX_INITIAL_RTR_ADVERTISEMENTS	3            /* transmissions */
#define MAX_FINAL_RTR_ADVERTISEMENTS	3            /* transmissions */
#define MIN_DELAY_BETWEEN_RAS		    3.0          /* seconds */
#define MAX_RA_DELAY_TIME		        (1000.0/2.0) /* milliseconds */

/* Node constants: */

#define MAX_MULTICAST_SOLICIT		    3 /* transmissions */
#define MAX_UNICAST_SOLICIT		        3 /* transmissions */
#define MAX_ANYCAST_DELAY_TIME		    1 /* transmissions */
#define MAX_NEIGHBOR_ADVERTISEMENT	    3 /* transmissions */
#define REACHABLE_TIME			        30000 /* milliseconds */

                                     
#define DELAY_FIRST_PROBE_TIME		    5 /* seconds */
#define MIN_RANDOM_FACTOR		        (1.0/2.0)
#define MAX_RANDOM_FACTOR		        (3.0/2.0)

#define MIN_MaxRtrAdvInterval		    4
#define MAX_MaxRtrAdvInterval		    1800

#define MIN_MinRtrAdvInterval		    3
#define MAX_MinRtrAdvInterval(netif)    (0.75 * (netif)->radv->MaxRtrAdvInterval)

#define MIN_AdvDefaultLifetime(netif)   (RADV_MAX(1,(netif)->radv->MaxRtrAdvInterval))
#define MAX_AdvDefaultLifetime		    9000

#define	MIN_AdvLinkMTU			        1280

#define MAX_AdvReachableTime		    3600000 /* 1 hour in milliseconds */

#define MAX_AdvCurHopLimit		        255

#define MAX_PrefixLen			        128

/*--------------------------------------------------------------------------*/
/* Prefix informations */
/*--------------------------------------------------------------------------*/

struct radv_prefix {
	struct radv_prefix 		*next;

	struct ip_addr          	Prefix;
	u8_t  PrefixLen;
	u8_t  AdvOnLinkFlag;        /* true/false */
	u8_t  AdvAutonomousFlag;    /* true/false */
	u32_t AdvValidLifetime;     /* seconds */
	u32_t AdvPreferredLifetime; /* seconds */
};

#define DFLT_AdvOnLinkFlag		    TRUE
#define DFLT_AdvAutonomousFlag		TRUE
#define DFLT_AdvValidLifetime		2592000 
#define DFLT_AdvPreferredLifetime	604800 


struct radv_prefix *radv_prefix_list_alloc();
void radv_prefix_list_free(struct radv_prefix *el);

/*--------------------------------------------------------------------------*/
/* Interface informations */
/*--------------------------------------------------------------------------*/

/* See Rfc 2461 - 6.2.1.  Router Configuration Variables */

struct radv {
	//int				if_prefix_len;

	u8_t  AdvSendAdvert;        /* true/false */
	u32_t MaxRtrAdvInterval;    /* seconds */
	u32_t MinRtrAdvInterval;    /* seconds */
	u32_t MinDelayBetweenRAs ;  /* seconds */
	u8_t  AdvManagedFlag;       /* true/false */
	u8_t  AdvOtherConfigFlag;   /* true/false */
	u32_t AdvLinkMTU;           /* integer */
	u32_t AdvReachableTime;     /* millisecond */
	u32_t AdvRetransTimer;      /* milliseconds */
	u8_t  AdvCurHopLimit;       /* integer */
	u16_t AdvDefaultLifetime;   /* seconds */
	u8_t  AdvSourceLLAddress;   /* true/false */
	u8_t  UnicastOnly;          /* true/false */

	struct radv_prefix   	        *prefix_list;


	/* Is true if we received a RS before the MinDelayBetweenRAs timeout*/
	u8_t  solicited_received; 
	/* True if MinDelayBetweenRAs has been reached */
	u8_t  min_delay_RA_reached;



	/* This option is not in the original RFC */
	//int			AdvDefaultPreference;
};

#define DFLT_AdvSendAdv			        FALSE
#define DFLT_MaxRtrAdvInterval		    600
#define DFLT_MinRtrAdvInterval(rinfo)	(0.33 * (rinfo)->MaxRtrAdvInterval)
#define DFLT_MinDelayBetweenRAs		    MIN_DELAY_BETWEEN_RAS
#define DFLT_AdvManagedFlag		        FALSE
#define DFLT_AdvOtherConfigFlag		    FALSE
#define DFLT_AdvLinkMTU			        UNSPECIFIED
#define DFLT_AdvReachableTime		    UNSPECIFIED
#define DFLT_AdvRetransTimer		    UNSPECIFIED
#define DFLT_AdvCurHopLimit		        64  
#define DFLT_AdvDefaultLifetime(rinfo)	RADV_MAX(1, (int)(3.0 * (rinfo)->MaxRtrAdvInterval))
#define DFLT_AdvSourceLLAddress		    TRUE
#define DFLT_UnicastOnly		        FALSE


void ip_radv_data_init(struct radv *rinfo);
void ip_radv_data_reset(struct radv *rinfo);

void ip_radv_netif_init(struct netif *netif);
void ip_radv_netif_reset(struct netif *netif);

/*--------------------------------------------------------------------------*/
/* Global functions */
/*--------------------------------------------------------------------------*/

/* Called by ip_init() */
void ip_radv_init(void);

/* Called when netif goes UP */
void ip_radv_start(struct netif *netif);

/* Called when netif goes DOWN */
void ip_radv_stop(struct netif *netif);

/* FIX: Call at Stack shutdown */
void ip_radv_shutdown(struct netif *netif);

/* Retuns <=0 if any RA option is invalid */
int ip_radv_check_options(struct netif *netif);


struct ip_hdr;
struct pbuf;
struct icmp_rs_hdr;

/* Called by ICMP level when Router Solicitation messages are received */
void ip_radv_handle_rs(struct netif *netif, struct pbuf *p, struct ip_hdr *iphdr, struct icmp_rs_hdr *irs);

/*--------------------------------------------------------------------------*/
/* Debug */
/*--------------------------------------------------------------------------*/

void ip_radv_data_dump(struct radv *rinfo);

#endif    /* LWIP_IP_RADV_H */

#endif   /* IPv6_ROUTER_ADVERTISEMENT */
