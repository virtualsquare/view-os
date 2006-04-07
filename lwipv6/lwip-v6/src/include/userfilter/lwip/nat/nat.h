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
/* Some costatns */
/*--------------------------------------------------------------------------*/

// for functions 
#define INLINE   __inline__
#define HIDDEN   static

// for structures 
#define PRAGMA_PACKED  __attribute__ ((__packed__))

// Time costants
#define SECOND   1000  
#define MINUTE   (SECOND*60)
#define HOUR     (MINUTE*60)

/*--------------------------------------------------------------------------*/
/* IP packets (pbuf) directions */
/*--------------------------------------------------------------------------*/

/* Direction of a packet */
typedef enum {
	CONN_DIR_ORIGINAL,
	CONN_DIR_REPLY,
	CONN_DIR_MAX
} conn_dir_t;

#define STR_DIRECTIONNAME(dir) ( \
	(dir)==CONN_DIR_ORIGINAL ? "ORIGINAL": \
	(dir)==CONN_DIR_REPLY    ? "REPLY"   : \
	"***BUG***" )

/*--------------------------------------------------------------------------*/
/* Connection tuple data */
/*--------------------------------------------------------------------------*/

struct proto_info {
	u8_t protonum;
	// FIX: use a union
	struct { u16_t port;          } tcp;
	struct { u16_t port;          } udp;
	struct { u8_t type, code, id; } icmp4;
	struct { u8_t type, code, id; } icmp6;
	// Add other protocols here. 
	u_int32_t all;
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

#define STR_NATNAME(dir) ( \
	(dir)==NAT_NONE       ? "(NONE)"     : \
	(dir)==NAT_SNAT       ? "SNAT"       : \
	(dir)==NAT_DNAT       ? "DNAT"       : \
	(dir)==NAT_MASQUERADE ? "MASQUERADE" : \
	"***BUG***" )

/*--------------------------------------------------------------------------*/
/* NAT process controll blocks */
/*--------------------------------------------------------------------------*/

// Max number of session the module can handle
#ifndef MEMP_NUM_NAT_PCB
#define MEMP_NUM_NAT_PCB    32
#endif


#include "lwip/nat/nat_track_tcp.h"

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
	u32_t refcount;

	struct netif *iface;   // Interface linked with NAT session

	/* Connection's tuples in both directions. If connection is NATed, 
	   CONN_DIR_REPLY tuple's fieald are modifed. CONN_DIR_REPLY 
	   tuple is fixed. */
	struct ip_tuple tuple[CONN_DIR_MAX];

	enum track_status status;

	u32_t timeout;

	union track_data  {
		struct { tcpstate_t state; } tcp;
		struct { u8_t  isstream; } udp;
		struct { u32_t count; } icmp4;
		struct { u32_t count; } icmp6;
		struct ip_ct_tcp  TCP;
	} proto;

	/* NAT DATA */
	nat_type_t nat_type;   
};

extern struct nat_pcb *nat_active_pcbs; // List of all active IPv4 NAT PCBs 

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
#include "lwip/nat/nat_track_tcp.h"
#include "lwip/nat/nat_track_icmp.h"

extern struct track_protocol  tcp_track;
extern struct track_protocol  udp_track;
extern struct track_protocol  icmp4_track;
extern struct track_protocol  icmp6_track;
extern struct track_protocol  default_track;

/*--------------------------------------------------------------------------*/
/* NAT functions */
/*--------------------------------------------------------------------------*/

int nat_init(void);

/* Functions used by NAT modules */
INLINE void nat_chksum_adjust(u8_t * chksum, u8_t * optr, s16_t olen, u8_t * nptr, s16_t nlen);

int  conn_remove_timer(struct nat_pcb *pcb);
void conn_refresh_timer(u32_t timeout, struct nat_pcb *pcb);
void conn_force_timeout(struct nat_pcb *pcb);

#endif  /* NAT_H */

#endif  /* LWIP_UNAT */

