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


#ifndef _NAT_TRACK_TCP_H
#define _NAT_TRACK_TCP_H



typedef enum {
	TCPS_NONE       = 0x0000,
	TCPS_OPEN       = 0x0001, 
	TCPS_FIN_SRC    = 0x0010, 
	TCPS_FIN_DST    = 0x0020, 
	TCPS_CLOSE_MASK = (TCPS_FIN_SRC | TCPS_FIN_DST)
} tcpstate_t;

#define NAT_TCP_CLOSING(state) ( ((state) == TCPS_FIN_DST) ||  ((state) == TCPS_FIN_SRC))


/**************************************************************************/
/**************************************************************************/
/**************************************************************************/
/**************************************************************************/

enum tcp_conntrack {
	TCP_CONNTRACK_NONE,
	TCP_CONNTRACK_SYN_SENT,
	TCP_CONNTRACK_SYN_RECV,
	TCP_CONNTRACK_ESTABLISHED,
	TCP_CONNTRACK_FIN_WAIT,
	TCP_CONNTRACK_CLOSE_WAIT,
	TCP_CONNTRACK_LAST_ACK,
	TCP_CONNTRACK_TIME_WAIT,
	TCP_CONNTRACK_CLOSE,
	TCP_CONNTRACK_LISTEN,
	TCP_CONNTRACK_MAX,
	TCP_CONNTRACK_IGNORE
};

#define TCP_STRSTATE(x) ( \
	(x)==TCP_CONNTRACK_NONE        ? "TCP_CONNTRACK_NONE" : \
	(x)==TCP_CONNTRACK_SYN_SENT    ? "TCP_CONNTRACK_SYN_SENT" : \
	(x)==TCP_CONNTRACK_SYN_RECV    ? "TCP_CONNTRACK_SYN_RECV" : \
	(x)==TCP_CONNTRACK_ESTABLISHED ? "TCP_CONNTRACK_ESTABLISHED" : \
	(x)==TCP_CONNTRACK_FIN_WAIT    ? "TCP_CONNTRACK_FIN_WAIT" : \
	(x)==TCP_CONNTRACK_CLOSE_WAIT  ? "TCP_CONNTRACK_CLOSE_WAIT" : \
	(x)==TCP_CONNTRACK_LAST_ACK    ? "TCP_CONNTRACK_LAST_ACK" : \
	(x)==TCP_CONNTRACK_TIME_WAIT   ? "TCP_CONNTRACK_TIME_WAIT" : \
	(x)==TCP_CONNTRACK_CLOSE       ? "TCP_CONNTRACK_CLOSE" : \
	(x)==TCP_CONNTRACK_LISTEN      ? "TCP_CONNTRACK_LISTEN" : \
	(x)==TCP_CONNTRACK_MAX         ? "TCP_CONNTRACK_MAX" : \
	(x)==TCP_CONNTRACK_IGNORE      ? "TCP_CONNTRACK_IGNORE"  : \
	"XXXXXXXXX BUG XXXXXXXXXXX" )


/* Window scaling is advertised by the sender */
#define IP_CT_TCP_FLAG_WINDOW_SCALE		0x01

/* SACK is permitted by the sender */
#define IP_CT_TCP_FLAG_SACK_PERM		0x02

/* This sender sent FIN first */
#define IP_CT_TCP_FLAG_CLOSE_INIT		0x03

struct ip_ct_tcp_state {
	u32_t	td_end;		/* max of seq + len */
	u32_t	td_maxend;	/* max of ack + max(win, 1) */
	u32_t	td_maxwin;	/* max(win) */
	u8_t	td_scale;	/* window scale factor */
	u8_t	loose;		/* used when connection picked up from the middle */
	u8_t	flags;		/* per direction options */
};

struct ip_ct_tcp
{
	struct ip_ct_tcp_state seen[2];	/* connection parameters per direction */
	u8_t	state;		/* state of the connection (enum tcp_conntrack) */

	/* For detecting stale connections */
	u8_t	last_dir;	/* Direction of the last packet (enum ip_conntrack_dir) */
	u8_t	retrans;	/* Number of retransmitted packets */
	u8_t	last_index;	/* Index of the last packet */
	u32_t	last_seq;	/* Last sequence number seen in dir */
	u32_t	last_ack;	/* Last sequence number seen in opposite dir */
	u32_t	last_end;	/* Last seq + len */
};


int ip_conntrack_protocol_tcp_lockinit(void);


#endif



