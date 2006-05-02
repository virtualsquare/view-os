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

#ifdef LWIP_NAT

#ifndef __NAT_H__
#define __NAT_H__

#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/userfilter.h"


/*--------------------------------------------------------------------------*/
/* Costants for hook registration. */
/*--------------------------------------------------------------------------*/

#define UF_PRI_NAT_PREROUTING_TRACK			100
#define UF_PRI_NAT_PREROUTING_DNAT			200

#define UF_PRI_NAT_INPUT_CONFIRM                        100

#define UF_PRI_NAT_OUTPUT_TRACK                         100

#define UF_PRI_NAT_POSTROUTING_SNAT			100
#define UF_PRI_NAT_POSTROUTING_CONFIRM                  200


/* NAT Hooks
 *                        +----- APPS -----+
 *                        |                |
 *                 INPUT [C]              [T] OUTPUT
 *                        |                |
 *                        |                | 
 *            PREROUTING  |    FORWARD     |  POSTROUTING
 *   netif -+-->[T][N]-->-+--->--[ ]--->---+->--[N][C]--+-> netif
 *          |                                           |
 *          +-------------<--------------<--------------+
 *
 *   [T}rak     = New valid connection are tracked for possible NAT
 *   [N]at      = Rules are checked and NAT is performed
 *   [C]confirm = timeout is set or refreshed and if packet reach this 
 *                hook the new connections is confirmed and expire .
 */

/*--------------------------------------------------------------------------*/
/* IP packets (pbuf) directions */
/*--------------------------------------------------------------------------*/

/* Direction of a packet */
typedef enum {
	CONN_DIR_ORIGINAL,
	CONN_DIR_REPLY,
	CONN_DIR_MAX
} conn_dir_t;

/*--------------------------------------------------------------------------*/
/* Connection tuple data */
/*--------------------------------------------------------------------------*/

struct proto_info {
	u8_t protonum;
	union {
		struct { u16_t port;                } tcp;
		struct { u16_t port;                } udp;
		struct { u8_t type, code; u16_t id; } icmp4;
		struct { u8_t type, code; u16_t id; } icmp6;
		u_int32_t all;
	} upi;
};

struct ip_pair {
	/* Use 128bit addresses for both IPv4 and IPv6 */
	struct ip_addr    ip;
	struct proto_info proto;
};

struct ip_tuple {
	u8_t ipv;
	struct ip_pair src;
	struct ip_pair dst;
};


/*--------------------------------------------------------------------------*/
/* NAT costants */
/*--------------------------------------------------------------------------*/

// Type of supported NAT 
typedef enum {
	NAT_NONE = 0,
	NAT_SNAT,
	NAT_DNAT,
	NAT_MASQUERADE,
} nat_type_t;

/*--------------------------------------------------------------------------*/
/* NAT process controll blocks */
/*--------------------------------------------------------------------------*/

// Max number of session the module can handle
#ifndef MEMP_NUM_NAT_PCB
#define MEMP_NUM_NAT_PCB    32
#endif


#include "lwip/nat/nat_track_tcp.h"
#include "lwip/nat/nat_track_udp.h"
#include "lwip/nat/nat_track_icmp.h"

enum track_status {

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	TS_SEEN_REPLY_BIT   = 1,
	TS_SEEN_REPLY       = (1 << TS_SEEN_REPLY_BIT),

	/* Connection is confirmed: originating packet has NATed successfully */
	TS_CONFIRMED_BIT    = 2,
	TS_CONFIRMED        = (1 << TS_CONFIRMED_BIT),

	/* Connection is dying (removed from lists), can not be unset. */
	TS_DYING_BIT        = 3,
	TS_DYING            = (1 << TS_DYING_BIT),

	/* Which kind of NAT has been tryed so far */
	TS_SNAT_TRY_BIT     = 4,
	TS_SNAT_TRY         = (1 << TS_SNAT_TRY_BIT),
	TS_DNAT_TRY_BIT     = 5,
	TS_DNAT_TRY         = (1 << TS_DNAT_TRY_BIT),
	TS_NAT_TRY_MASK     = (TS_SNAT_TRY | TS_DNAT_TRY),

	TS_MASQUERADE_BIT   = 8,
	TS_MASQUERADE       = (1 << TS_MASQUERADE_BIT ),
};


/*
 * NAT Process Control Block
 */
struct nat_pcb 
{
	struct nat_pcb  *next; // For the linked list 

	unsigned int id;
	u32_t        refcount;

	/* Tracking data */

	enum track_status status;

	/* Connection's tuples in both directions. For NATed connections, 
	   CONN_DIR_REPLY tuple's fieald are modifed. CONN_DIR_ORIGINAL
	   tuple is fixed and never changes */
	struct ip_tuple tuple[CONN_DIR_MAX];

	u32_t timeout;      /* mseconds */

	union track_data  {
		struct ip_ct_tcp  TCP;
		struct ip_ct_udp  udp;
		struct ip_ct_icmp icmp4;
		struct ip_ct_icmp icmp6;
	} proto;

	/* NAT info */

	nat_type_t nat_type;   

	struct netif *iface;   // Interface linked with NAT session
};

extern struct nat_pcb *nat_active_pcbs; // List of all active IPv4 NAT PCBs 

/*--------------------------------------------------------------------------*/
/* NAT Rules */
/*--------------------------------------------------------------------------*/

// NAT operations are performed in several points. 
typedef enum {
	NAT_PREROUTING,
	NAT_POSTROUTING
} nat_table_t;

#include "lwip/nat/nat_rules.h"

/*--------------------------------------------------------------------------*/
/* Protocol handlers */
/*--------------------------------------------------------------------------*/

#include "lwip/nat/nat_track_protocol.h"

extern struct track_protocol  default_track;

/*--------------------------------------------------------------------------*/
/* Pbuf data & functions */
/*--------------------------------------------------------------------------*/

struct nat_info {
	u32_t  dir;
	struct nat_pcb *track;
};

void nat_pbuf_init(struct pbuf *p);
void nat_pbuf_get(struct pbuf *p);
void nat_pbuf_put(struct pbuf *p);
void nat_pbuf_reset(struct pbuf *p);

/*--------------------------------------------------------------------------*/
/* NAT functions */
/*--------------------------------------------------------------------------*/

int nat_init(void);

int  conn_remove_timer(struct nat_pcb *pcb);
void conn_refresh_timer(u32_t timeout, struct nat_pcb *pcb);
void conn_force_timeout(struct nat_pcb *pcb);

struct nat_pcb * conn_find_track(conn_dir_t *direction, struct ip_tuple * tuple );

/* Functions used by NAT modules */
void nat_chksum_adjust(u8_t * chksum, u8_t * optr, s16_t olen, u8_t * nptr, s16_t nlen);


/*--------------------------------------------------------------------------*/
/* Debug */
/*--------------------------------------------------------------------------*/

#ifdef LWIP_DEBUG

#define STR_DIRECTIONNAME(dir) ( \
	(dir)==CONN_DIR_ORIGINAL ? "ORIGINAL": \
	(dir)==CONN_DIR_REPLY    ? "REPLY"   : \
	"***BUG***" )

#define STR_NATNAME(dir) ( \
	(dir)==NAT_NONE       ? "(NONE)"     : \
	(dir)==NAT_SNAT       ? "SNAT"       : \
	(dir)==NAT_DNAT       ? "DNAT"       : \
	(dir)==NAT_MASQUERADE ? "MASQUERADE" : \
	"***BUG***" )

#endif


#endif  /* NAT_H */

#endif  /* LWIP_UNAT */




		//struct { tcpstate_t state; } tcp;
		//struct { u8_t  isstream; } udp;
		//struct { u32_t count; } icmp4;
		//struct { u32_t count; } icmp6;

