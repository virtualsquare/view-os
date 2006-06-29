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

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>:
 *      - Real stateful connection tracking
 *      - Modified state transitions table
 *      - Window scaling support added
 *      - SACK support added
 *
 * Willy Tarreau:
 *      - State table bugfixes
 *      - More robust state changes
 *      - Tuning timer parameters
 *
 * version 2.2
 */

//#ifdef LWIP_NAT
#if defined(LWIP_USERFILTER) && defined (LWIP_NAT)

#include "lwip/debug.h"
#include "lwip/memp.h" /* MEMP_NAT_RULE */
#include "lwip/sys.h"

#include "lwip/inet.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "netif/etharp.h"

#include "lwip/netif.h"
#include "lwip/userfilter.h"


#include "lwip/nat/nat.h"
#include "lwip/nat/nat_tables.h"

#ifndef NAT_DEBUG
#define NAT_DEBUG   DBG_OFF
#endif

/*--------------------------------------------------------------------------*/

int track_tcp_tuple(struct ip_tuple *tuple, void *hdr)
{ 
	struct tcp_hdr       *tcphdr  = NULL;
	tcphdr = (struct tcp_hdr *) hdr;
	tuple->src.proto.upi.tcp.port = tcphdr->src;
	tuple->dst.proto.upi.tcp.port = tcphdr->dest;
	return 1;
}

int track_tcp_inverse(struct ip_tuple *reply, struct ip_tuple *tuple)  
{ 
	reply->src.proto.upi.tcp.port = tuple->dst.proto.upi.tcp.port;
	reply->dst.proto.upi.tcp.port = tuple->src.proto.upi.tcp.port;
	return 1;
}

/*--------------------------------------------------------------------------*/

int track_tcp_error (uf_verdict_t *verdict, struct pbuf *p)
{
	// FIX: check packet len and checksum
	return 1;
}


int nat_tcp_manip (nat_manip_t type, void *iphdr, int iplen, struct ip_tuple *inverse, 
		u8_t *iphdr_new_changed_buf, 
		u8_t *iphdr_old_changed_buf, 
		u32_t iphdr_changed_buflen)
{
	struct tcp_hdr       *tcphdr  = NULL;
	u16_t                 old_value;

	tcphdr = (struct tcp_hdr *) (iphdr+iplen);

	// Adjust tcp checksum
	nat_chksum_adjust((u8_t *) & tcphdr->chksum, 
		(u8_t *) iphdr_old_changed_buf, iphdr_changed_buflen, 
		(u8_t *) iphdr_new_changed_buf, iphdr_changed_buflen);

	// Set port
	if (type == MANIP_DST) {
		old_value    = tcphdr->dest;
		tcphdr->dest = inverse->src.proto.upi.tcp.port;
		nat_chksum_adjust((u8_t *) & tcphdr->chksum, (u8_t *) & old_value, 2, (u8_t *) & tcphdr->dest, 2);
	}
	else if (type == MANIP_SRC) {
		old_value=     tcphdr->src;
		tcphdr->src  = inverse->dst.proto.upi.tcp.port;
		nat_chksum_adjust((u8_t *) & tcphdr->chksum, (u8_t *) & old_value, 2, (u8_t *) & tcphdr->src, 2);
	}

	return 1;
}

int nat_tcp_tuple_inverse (struct ip_tuple *reply, struct ip_tuple *tuple, nat_type_t type, struct manip_range *nat_manip )
{
	u16_t port;
	u32_t min, max;

	if (type == NAT_SNAT) {

		if (nat_manip->flag & MANIP_RANGE_PROTO) {
			min = nat_manip->protomin.value;
			max = nat_manip->protomax.value;
		}
		else {
			min = 0;
			max = 0xFFFF;
		}

		if (nat_ports_getnew(IP_PROTO_TCP, &port, min, max) > 0) {
			reply->dst.proto.upi.tcp.port = htons(port); 
		}
		else 
			return -1;
	} 
	else if (type == NAT_DNAT) {

		if (nat_manip->flag & MANIP_RANGE_PROTO) {
			reply->src.proto.upi.tcp.port = nat_manip->protomin.value;
		}
	}

	return 1;
}


int nat_tcp_free (struct nat_pcb *pcb)
{
	if (pcb->nat_type == NAT_SNAT) {
		nat_ports_free(IP_PROTO_TCP, ntohs(pcb->tuple[CONN_DIR_REPLY].dst.proto.upi.tcp.port));

	} 

	return 1;
}



/*--------------------------------------------------------------------------*/
/*  Code from GNU/Linux Netfilter/IPtables code. */
/*--------------------------------------------------------------------------*/

#define NF_ACCEPT    UF_ACCEPT
#define NF_DROP      UF_DROP
#define NF_REPEAT    UF_REPEAT


#define	skb_header_pointer(skb, offset, len, buffer) (((char*)(skb)->payload)+offset)

#define write_lock_bh(x)       sys_sem_wait  ((*(x)))
#define write_unlock_bh(x)     sys_sem_signal((*(x)))
#define read_lock_bh(x)        sys_sem_wait  ((*(x)))
#define read_unlock_bh(x)      sys_sem_signal((*(x)))


# define TCPOPT_EOL             0
# define TCPOPT_NOP             1
# define TCPOPT_MAXSEG          2
# define TCPOLEN_MAXSEG         4
# define TCPOPT_WINDOW          3
# define TCPOLEN_WINDOW         3
# define TCPOPT_SACK_PERMITTED  4               /* Experimental */
# define TCPOLEN_SACK_PERMITTED 2
# define TCPOPT_SACK            5               /* Experimental */
# define TCPOPT_TIMESTAMP       8
# define TCPOLEN_TIMESTAMP      10
# define TCPOLEN_TSTAMP_APPA    (TCPOLEN_TIMESTAMP+2) /* appendix A */
# define TCPOPT_TSTAMP_HDR      \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
//#define TCP_MSS        512
#define TCP_MAXWIN     65535   /* largest value for (unscaled) window */
#define TCP_MAX_WINSHIFT       14      /* maximum window shift */
#define SOL_TCP                6       /* TCP level */


/*
 *      TCP option
 */
#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
/*
 *     TCP option lengths
 */
#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED          12
#define TCPOLEN_WSCALE_ALIGNED          4
#define TCPOLEN_SACKPERM_ALIGNED        4
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_BASE_ALIGNED       4
#define TCPOLEN_SACK_PERBLOCK           8




/*
 * net/tcp.h
 */
  /*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int before(u32_t seq1, u32_t seq2)
{
	return ((s32_t)(seq1-seq2)) < 0;
}

static inline int after(u32_t seq1, u32_t seq2)
{
	return ((s32_t)(seq2-seq1)) < 0;
}

/* is s2<=s1<=s3 ? */
static inline  int between(u32_t seq1, u32_t seq2, u32_t seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

/* Protects conntrack->proto.tcp */
/*static DEFINE_RWLOCK(tcp_lock);*/
sys_sem_t tcp_lock;

/* "Be conservative in what you do, 
    be liberal in what you accept from others." 
    If it's non-zero, we mark only out of window RST segments as INVALID. */
int ip_ct_tcp_be_liberal = 0;

/* When connection is picked up from the middle, how many packets are required
   to pass in each direction when we assume we are in sync - if any side uses
   window scaling, we lost the game. 
   If it is set to zero, we disable picking up already established 
   connections. */
//int ip_ct_tcp_loose = 3;
int ip_ct_tcp_loose = 0;

/* Max number of the retransmitted packets without receiving an (acceptable) 
   ACK from the destination. If this number is reached, a shorter timer 
   will be started. */
int ip_ct_tcp_max_retrans = 3;

  /* FIXME: Examine ipfilter's timeouts and conntrack transitions more
     closely.  They're more complex. --RR */

#if 0
static const char *tcp_conntrack_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};
#endif

/* ATTENTION: lwip uses microseconds!!! */
#define HZ 1000  

#define SECS * HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

unsigned long ip_ct_tcp_timeout_syn_sent =      2 MINS;
unsigned long ip_ct_tcp_timeout_syn_recv =     60 SECS;
unsigned long ip_ct_tcp_timeout_established =   5 DAYS;
unsigned long ip_ct_tcp_timeout_fin_wait =      2 MINS;
unsigned long ip_ct_tcp_timeout_close_wait =   60 SECS;
unsigned long ip_ct_tcp_timeout_last_ack =     30 SECS;
unsigned long ip_ct_tcp_timeout_time_wait =     2 MINS;
unsigned long ip_ct_tcp_timeout_close =        10 SECS;

/* RFC1122 says the R2 limit should be at least 100 seconds.
   Linux uses 15 packets as limit, which corresponds 
   to ~13-30min depending on RTO. */
unsigned long ip_ct_tcp_timeout_max_retrans =     5 MINS;
 
static unsigned long * tcp_timeouts[]
= { NULL,                              /*      TCP_CONNTRACK_NONE */
    &ip_ct_tcp_timeout_syn_sent,       /*      TCP_CONNTRACK_SYN_SENT, */
    &ip_ct_tcp_timeout_syn_recv,       /*      TCP_CONNTRACK_SYN_RECV, */
    &ip_ct_tcp_timeout_established,    /*      TCP_CONNTRACK_ESTABLISHED,      */
    &ip_ct_tcp_timeout_fin_wait,       /*      TCP_CONNTRACK_FIN_WAIT, */
    &ip_ct_tcp_timeout_close_wait,     /*      TCP_CONNTRACK_CLOSE_WAIT,       */
    &ip_ct_tcp_timeout_last_ack,       /*      TCP_CONNTRACK_LAST_ACK, */
    &ip_ct_tcp_timeout_time_wait,      /*      TCP_CONNTRACK_TIME_WAIT,        */
    &ip_ct_tcp_timeout_close,          /*      TCP_CONNTRACK_CLOSE,    */
    NULL,                              /*      TCP_CONNTRACK_LISTEN */
 };
 
#define sNO TCP_CONNTRACK_NONE
#define sSS TCP_CONNTRACK_SYN_SENT
#define sSR TCP_CONNTRACK_SYN_RECV
#define sES TCP_CONNTRACK_ESTABLISHED
#define sFW TCP_CONNTRACK_FIN_WAIT
#define sCW TCP_CONNTRACK_CLOSE_WAIT
#define sLA TCP_CONNTRACK_LAST_ACK
#define sTW TCP_CONNTRACK_TIME_WAIT
#define sCL TCP_CONNTRACK_CLOSE
#define sLI TCP_CONNTRACK_LISTEN
#define sIV TCP_CONNTRACK_MAX
#define sIG TCP_CONNTRACK_IGNORE

/* What TCP flags are set from RST/SYN/FIN/ACK. */
enum tcp_bit_set {
	TCP_SYN_SET,
	TCP_SYNACK_SET,
	TCP_FIN_SET,
	TCP_ACK_SET,
	TCP_RST_SET,
	TCP_NONE_SET,
};
  
/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments 
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:	initial state
 * SYN_SENT:	SYN-only packet seen 
 * SYN_RECV:	SYN-ACK packet seen
 * ESTABLISHED:	ACK packet seen
 * FIN_WAIT:	FIN packet seen
 * CLOSE_WAIT:	ACK seen (after FIN) 
 * LAST_ACK:	FIN seen (after FIN)
 * TIME_WAIT:	last ACK seen
 * CLOSE:	closed connection
 *
 * LISTEN state is not used.
 *
 * Packets marked as IGNORED (sIG):
 *	if they may be either invalid or valid 
 *	and the receiver may send back a connection 
 *	closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *	if they are invalid
 *	or we do not support the request (simultaneous open)
 */
static enum tcp_conntrack tcp_conntracks[2][6][TCP_CONNTRACK_MAX] = {
	{
/* ORIGINAL */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*syn*/	   { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sIV },
/*
 *	sNO -> sSS	Initialize a new connection
 *	sSS -> sSS	Retransmitted SYN
 *	sSR -> sIG	Late retransmitted SYN?
 *	sES -> sIG	Error: SYNs in window outside the SYN_SENT state
 *			are errors. Receiver will reply with RST 
 *			and close the connection.
 *			Or we are not in sync and hold a dead connection.
 *	sFW -> sIG
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sSS	Reopened connection (RFC 1122).
 *	sCL -> sSS
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*synack*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV },
/*
 * A SYN/ACK from the client is always invalid:
 *	- either it tries to set up a simultaneous open, which is 
 *	  not supported;
 *	- or the firewall has just been inserted between the two hosts
 *	  during the session set-up. The SYN will be retransmitted 
 *	  by the true client (or it'll time out).
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sNO -> sIV	Too late and no reason to do anything...
 *	sSS -> sIV	Client migth not send FIN in this state:
 *			we enforce waiting for a SYN/ACK reply first.
 *	sSR -> sFW	Close started.
 *	sES -> sFW	
 *	sFW -> sLA	FIN seen in both directions, waiting for
 *			the last ACK. 
 *			Migth be a retransmitted FIN as well...
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN. Remain in the same state.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*ack*/	   { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *	sNO -> sES	Assumed.
 *	sSS -> sIV	ACK is invalid: we haven't seen a SYN/ACK yet.
 *	sSR -> sES	Established state is reached.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected.
 *	sTW -> sTW	Retransmitted last ACK. Remain in the same state.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sIV },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	},
	{
/* REPLY */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*syn*/	   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV },
/*
 *	sNO -> sIV	Never reached.
 *	sSS -> sIV	Simultaneous open, not supported
 *	sSR -> sIV	Simultaneous open, not supported.
 *	sES -> sIV	Server may not initiate a connection.
 *	sFW -> sIV
 *	sCW -> sIV
 *	sLA -> sIV
 *	sTW -> sIV	Reopened connection, but server may not do it.
 *	sCL -> sIV
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*synack*/ { sIV, sSR, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sIV },
/*
 *	sSS -> sSR	Standard open.
 *	sSR -> sSR	Retransmitted SYN/ACK.
 *	sES -> sIG	Late retransmitted SYN/ACK?
 *	sFW -> sIG	Might be SYN/ACK answering ignored SYN
 *	sCW -> sIG
 *	sLA -> sIG
 *	sTW -> sIG
 *	sCL -> sIG
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*fin*/    { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *	sSS -> sIV	Server might not send FIN in this state.
 *	sSR -> sFW	Close started.
 *	sES -> sFW
 *	sFW -> sLA	FIN seen in both directions.
 *	sCW -> sLA
 *	sLA -> sLA	Retransmitted FIN.
 *	sTW -> sTW
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*ack*/	   { sIV, sIV, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *	sSS -> sIV	Might be a half-open connection.
 *	sSR -> sSR	Might answer late resent SYN.
 *	sES -> sES	:-)
 *	sFW -> sCW	Normal close request answered by ACK.
 *	sCW -> sCW
 *	sLA -> sTW	Last ACK detected.
 *	sTW -> sTW	Retransmitted last ACK.
 *	sCL -> sCL
 */
/* 	     sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sLI	*/
/*rst*/    { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sIV },
/*none*/   { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
  	}
};


static unsigned int get_conntrack_index(const struct tcp_hdr *tcph)
{
	if ( TCPH_FLAGS(tcph) & TCP_RST) return TCP_RST_SET;
	else if ( TCPH_FLAGS(tcph) & TCP_SYN) return ((TCPH_FLAGS(tcph) & TCP_ACK) ? TCP_SYNACK_SET : TCP_SYN_SET);
	else if ( TCPH_FLAGS(tcph) & TCP_FIN) return TCP_FIN_SET;
	else if ( TCPH_FLAGS(tcph) & TCP_ACK) return TCP_ACK_SET;
	else return TCP_NONE_SET;
}

static inline u32_t segment_seq_plus_len(u32_t seq,
					 size_t len,
					 void *iph,
					 struct tcp_hdr *tcph)
{
	int iplen;
	struct ip4_hdr *ip4hdr = (struct ip4_hdr *) iph;
	struct ip_hdr  *ip6hdr = (struct ip_hdr *) iph;
	if (IPH_V(ip6hdr) == 6)      iplen = IP_HLEN;
	else if (IPH_V(ip6hdr) == 4) iplen = IPH4_HL(ip4hdr)*4;

	return (  seq + len - 
		(iplen + ( TCPH_HDRLEN(tcph)*4)) + 
		((TCPH_FLAGS(tcph) & TCP_SYN) ? 1 : 0) + 
		((TCPH_FLAGS(tcph) & TCP_FIN) ? 1 : 0));
}

/* Fixme: what about big packets? */
#define MAXACKWINCONST			66000
#define MAXACKWINDOW(sender)						\
	((sender)->td_maxwin > MAXACKWINCONST ? (sender)->td_maxwin	\
					      : MAXACKWINCONST)
  
/*
 * Simplified tcp_parse_options routine from tcp_input.c
 */
static void tcp_options(const struct pbuf *skb,
			void *iph,
			struct tcp_hdr *tcph, 
			struct ip_ct_tcp_state *state)
{
//	unsigned char buff[(15 * 4) - sizeof(struct tcp_hdr)];
	unsigned char *ptr;
	int length = ( TCPH_HDRLEN(tcph)*4) - sizeof(struct tcp_hdr);

	/* added by Diego Billi */
	int iplen;
	struct ip4_hdr *ip4hdr = (struct ip4_hdr *) iph;
	struct ip_hdr  *ip6hdr = (struct ip_hdr *) iph;

	if (IPH_V(ip6hdr) == 6)      iplen = IP_HLEN;
	else if (IPH_V(ip6hdr) == 4) iplen = IPH4_HL(ip4hdr) * 4;

	//LWIP_DEBUGF(NAT_DEBUG, ("%s: length=%d.\n", __func__, length));		
	
	if (!length) {
		return;
	}

	ptr = (unsigned char *) skb_header_pointer(skb, iplen + sizeof(struct tcp_hdr), length, buff);

	state->td_scale = state->flags = 0;
	
	while (length > 0) {
		int opcode=*ptr++;
		int opsize;
		
		switch (opcode) {
		case TCPOPT_EOL: 
			return;
		case TCPOPT_NOP:	// Ref: RFC 793 section 3.1 
			length--;
			continue;
		default:
			opsize=*ptr++;
			if (opsize < 2) { // "silly options" 
				return;
			}

			if (opsize > length) {
				break;	// don't parse partial options 
			}

			if (opcode == TCPOPT_SACK_PERM && opsize == TCPOLEN_SACK_PERM) {
				state->flags |= IP_CT_TCP_FLAG_SACK_PERM;
			} else if (opcode == TCPOPT_WINDOW && opsize == TCPOLEN_WINDOW) {
				state->td_scale = *(u8_t *)ptr;
				if (state->td_scale > 14) {
					// See RFC1323 
					state->td_scale = 14;
				}
				state->flags |=	IP_CT_TCP_FLAG_WINDOW_SCALE;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}
}

static void tcp_sack(const struct pbuf *skb,
		     void  *iph,
		     struct tcp_hdr *tcph,
		     u32_t *sack)
{
	//unsigned char buff[(15 * 4) - sizeof(struct tcp_hdr)];
	unsigned char *ptr;
	int length = ( TCPH_HDRLEN(tcph)*4) - sizeof(struct tcp_hdr);
	u32_t tmp;

	/* added by Diego Billi */
	int iplen;
	struct ip4_hdr *ip4hdr = (struct ip4_hdr *) iph;
	struct ip_hdr  *ip6hdr = (struct ip_hdr *) iph;
	if (IPH_V(ip6hdr) == 6)      iplen = IP_HLEN;
	else if (IPH_V(ip6hdr) == 4) iplen = IPH4_HL(ip4hdr) * 4;

	//LWIP_DEBUGF(NAT_DEBUG, ("%s: length=%d. %d %d\n", __func__, length, ( TCPH_HDRLEN(tcph)*4), sizeof(struct tcp_hdr)));		

	if (!length) {
		return;
	}

	ptr = (unsigned char *) skb_header_pointer(skb,	 iplen + sizeof(struct tcp_hdr), length, buff);
	//BUG_ON(ptr == NULL);

	/* Fast path for timestamp-only option */
	if (length == TCPOLEN_TSTAMP_ALIGNED*4
	    && *(u32_t *)ptr ==
//	        __constant_ntohl((TCPOPT_NOP << 24) 
	        	ntohl((TCPOPT_NOP << 24) 
	        		 | (TCPOPT_NOP << 16)
	        		 | (TCPOPT_TIMESTAMP << 8)
	        		 | TCPOLEN_TIMESTAMP)) {
		return;
	}
	
	while (length > 0) {
		int opcode=*ptr++;
		int opsize, i;
		
		switch (opcode) {
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:	// Ref: RFC 793 section 3.1 
			length--;
			continue;
		default:
			opsize=*ptr++;
			if (opsize < 2) { // "silly options"  
				return;
			}
			if (opsize > length) {
				break;	// don't parse partial options 
			}

			if (opcode == TCPOPT_SACK && 
			    opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK) && 
			    !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {

			    	for (i = 0;
			    	     i < (opsize - TCPOLEN_SACK_BASE);
			    	     i += TCPOLEN_SACK_PERBLOCK) {
					tmp = ntohl(*((u32_t *)(ptr+i)+1));
					
					if (after(tmp, *sack))
						*sack = tmp;
				}
				return;
			}
			ptr += opsize - 2;
			length -= opsize;
		}
	}

}

static int tcp_in_window(struct ip_ct_tcp *state, 
                         //enum ip_conntrack_dir dir,
			 u32_t dir,
                         unsigned int index,
                         const struct pbuf *skb,
                         void *iph,
                         struct tcp_hdr *tcph)
{
	struct ip_ct_tcp_state *sender   = &state->seen[dir];
	struct ip_ct_tcp_state *receiver = &state->seen[!dir];
	u32_t seq, ack, sack, end, win, swin;
	int res;


	/*
	 * Get the required data from the packet.
	 */
	seq = ntohl(tcph->seqno); /* ntohl(tcph->seq); */
	ack = sack = ntohl(tcph->ackno); /* ntohl(tcph->ack_seq); */
	win = ntohs(tcph->wnd); /* ntohs(tcph->window); */
	end = segment_seq_plus_len(seq, skb->tot_len, iph, tcph);

	
	if (receiver->flags & IP_CT_TCP_FLAG_SACK_PERM)
		tcp_sack(skb, iph, tcph, &sack);

	if (sender->td_end == 0) {
		/*
		 * Initialize sender data.
		 */
		if ((TCPH_FLAGS(tcph) & TCP_SYN) && (TCPH_FLAGS(tcph) & TCP_ACK)) {
			/*
			 * Outgoing SYN-ACK in reply to a SYN.
			 */
			sender->td_end = sender->td_maxend = end;
			sender->td_maxwin = (win == 0 ? 1 : win);

			tcp_options(skb, iph, tcph, sender);
			/* 
			 * RFC 1323:
			 * Both sides must send the Window Scale option
			 * to enable window scaling in either direction.
			 */
			if (!(sender->flags & IP_CT_TCP_FLAG_WINDOW_SCALE
			      && receiver->flags & IP_CT_TCP_FLAG_WINDOW_SCALE))
				sender->td_scale = 
				receiver->td_scale = 0;
		} else {
			/*
			 * We are in the middle of a connection,
			 * its history is lost for us.
			 * Let's try to use the data from the packet.
		 	 */
			sender->td_end = end;
			sender->td_maxwin = (win == 0 ? 1 : win);
			sender->td_maxend = end + sender->td_maxwin;
		}
	} else if (((state->state == TCP_CONNTRACK_SYN_SENT
		     //&& dir == IP_CT_DIR_ORIGINAL)
		     && dir == CONN_DIR_ORIGINAL)
		    || (state->state == TCP_CONNTRACK_SYN_RECV
		        //&& dir == IP_CT_DIR_REPLY))
		        && dir == CONN_DIR_REPLY))
		    && after(end, sender->td_end)) {
		/*
		 * RFC 793: "if a TCP is reinitialized ... then it need
		 * not wait at all; it must only be sure to use sequence 
		 * numbers larger than those recently used."
		 */
		sender->td_end =
		sender->td_maxend = end;
		sender->td_maxwin = (win == 0 ? 1 : win);

		tcp_options(skb, iph, tcph, sender);
	}

	
	if (!(TCPH_FLAGS(tcph) & TCP_ACK)) {
		/*
		 * If there is no ACK, just pretend it was set and OK.
		 */
		ack = sack = receiver->td_end;
		LWIP_DEBUGF(NAT_DEBUG, ("%s: 2e\n", __func__));		
	} else if (((TCPH_FLAGS(tcph) & (TCP_ACK|TCP_RST)) == (TCP_ACK|TCP_RST)) 
		   && (ack == 0)) {
		/*
		 * Broken TCP stacks, that set ACK in RST packets as well
		 * with zero ack value.
		 */
		ack = sack = receiver->td_end;
	}

	if (seq == end
	    && (!(TCPH_FLAGS(tcph) & TCP_RST) 
	        || (seq == 0 && state->state == TCP_CONNTRACK_SYN_SENT)))
		/*
		 * Packets contains no data: we assume it is valid
		 * and check the ack value only.
		 * However RST segments are always validated by their
		 * SEQ number, except when seq == 0 (reset sent answering
		 * SYN.
		 */
		seq = end = sender->td_end;


	if (sender->loose || receiver->loose ||
	    (before(seq, sender->td_maxend + 1) &&
	     after(end, sender->td_end - receiver->td_maxwin - 1) &&
	     before(sack, receiver->td_end + 1) &&
	     after(ack, receiver->td_end - MAXACKWINDOW(sender)))) {
	    	/*
		 * Take into account window scaling (RFC 1323).
		 */
		if (!(TCPH_FLAGS(tcph) & TCP_SYN))
			win <<= sender->td_scale;
		
		/*
		 * Update sender data.
		 */
		swin = win + (sack - ack);
		if (sender->td_maxwin < swin)
			sender->td_maxwin = swin;
		if (after(end, sender->td_end))
			sender->td_end = end;
		/*
		 * Update receiver data.
		 */
		if (after(end, sender->td_maxend))
			receiver->td_maxwin += end - sender->td_maxend;
		if (after(sack + win, receiver->td_maxend - 1)) {

			receiver->td_maxend = sack + win;
			if (win == 0)
				receiver->td_maxend++;
		}

		/* 
		 * Check retransmissions.
		 */
		if (index == TCP_ACK_SET) { 

			if (state->last_dir == dir
			    && state->last_seq == seq
			    && state->last_ack == ack
			    && state->last_end == end)
				state->retrans++;
			else {
				state->last_dir = dir;
				state->last_seq = seq;
				state->last_ack = ack;
				state->last_end = end;
				state->retrans = 0;
			}
		}
		/*
		 * Close the window of disabled window tracking :-)
		 */
		if (sender->loose)
			sender->loose--;
		
		res = 1;
	} else {
		res = ip_ct_tcp_be_liberal;
  	}

	return res;
}

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80

#if 0
/* table of valid flag combinations - ECE and CWR are always valid */
static u8_t tcp_valid_flags[(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG) + 1] =
{
	[TH_SYN]			= 1,
	[TH_SYN|TH_ACK]			= 1,
	[TH_SYN|TH_ACK|TH_PUSH]		= 1,
	[TH_RST]			= 1,
	[TH_RST|TH_ACK]			= 1,
	[TH_RST|TH_ACK|TH_PUSH]		= 1,
	[TH_FIN|TH_ACK]			= 1,
	[TH_ACK]			= 1,
	[TH_ACK|TH_PUSH]		= 1,
	[TH_ACK|TH_URG]			= 1,
	[TH_ACK|TH_URG|TH_PUSH]		= 1,
	[TH_FIN|TH_ACK|TH_PUSH]		= 1,
	[TH_FIN|TH_ACK|TH_URG]		= 1,
	[TH_FIN|TH_ACK|TH_URG|TH_PUSH]	= 1,
};
#endif



/* Returns verdict for packet, or -1 for invalid. */

static int track_tcp_handle2(uf_verdict_t *verdict, struct pbuf *skb, conn_dir_t direction)
{
	enum tcp_conntrack new_state, old_state;
	//enum ip_conntrack_dir dir;
	u32_t dir;
	unsigned long timeout;
	unsigned int index;

	struct nat_pcb *pcb = skb->nat.track;

	/* added by Diego Billi */
	int dataoff;
	struct ip4_hdr *iph = (struct ip4_hdr *) skb->payload;
	struct ip_hdr  *ip6hdr = (struct ip_hdr *) skb->payload;
	struct tcp_hdr *th;// _tcph;
	if (IPH_V(ip6hdr) == 6)      dataoff = IP_HLEN;
	else if (IPH_V(ip6hdr) == 4) dataoff = IPH4_HL(iph) * 4;

	
	th = (struct tcp_hdr *) skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	
	write_lock_bh(&tcp_lock);

	old_state = pcb->proto.TCP.state;
	//dir       = CTINFO2DIR(ctinfo);
	dir       = direction;
	index     = get_conntrack_index(th);
	new_state = tcp_conntracks[dir][index][old_state];

	LWIP_DEBUGF(NAT_DEBUG, ("%s: old=%s  new=%s\n", __func__,
		TCP_STRSTATE(old_state),
		TCP_STRSTATE(new_state)
	));


	switch (new_state) {
	case TCP_CONNTRACK_IGNORE:

		LWIP_DEBUGF(NAT_DEBUG, ("%s: CONNTRACK IGNORE\n", __func__));

		/* Either SYN in ORIGINAL
		 * or SYN/ACK in REPLY. */
		if (index == TCP_SYNACK_SET
		    && pcb->proto.TCP.last_index == TCP_SYN_SET
		    && pcb->proto.TCP.last_dir != dir
		    && ntohl(th->ackno) ==
		    	     pcb->proto.TCP.last_end) {
			/* This SYN/ACK acknowledges a SYN that we earlier 
			 * ignored as invalid. This means that the client and
			 * the server are both in sync, while the firewall is
			 * not. We kill this session and block the SYN/ACK so
			 * that the client cannot but retransmit its SYN and 
			 * thus initiate a clean new session.
			 */

		    	write_unlock_bh(&tcp_lock);

			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

		    	//return -NF_DROP;
			* verdict = UF_DROP;
			return -1;
		}
		pcb->proto.TCP.last_index = index;
		pcb->proto.TCP.last_dir   = dir;
		pcb->proto.TCP.last_seq   = ntohl(th->seqno);
		pcb->proto.TCP.last_end   = segment_seq_plus_len(ntohl(th->seqno), skb->tot_len, iph, th);
		
		write_unlock_bh(&tcp_lock);

		//return NF_ACCEPT;
		* verdict = UF_ACCEPT;
		return 1;

	case TCP_CONNTRACK_MAX:
		/* Invalid packet */
		write_unlock_bh(&tcp_lock);
//		return -NF_ACCEPT;
		* verdict = UF_ACCEPT;
		return -1;


	case TCP_CONNTRACK_SYN_SENT:
		if (old_state < TCP_CONNTRACK_TIME_WAIT)
			break;
		if ((pcb->proto.TCP.seen[dir].flags & IP_CT_TCP_FLAG_CLOSE_INIT)
		    || after(ntohl(th->seqno),
		    	     pcb->proto.TCP.seen[dir].td_end)) {	
		    	/* Attempt to reopen a closed connection.
		    	* Delete this connection and look up again. */
		    	write_unlock_bh(&tcp_lock);

			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

			LWIP_DEBUGF(NAT_DEBUG, ("%s: need REPEAT\n", __func__));

		    	//return -NF_REPEAT;
			* verdict = UF_REPEAT;
			return -1;

		} else {
			write_unlock_bh(&tcp_lock);
			//return -NF_ACCEPT;
			* verdict = UF_ACCEPT;
			return -1;
		}
	case TCP_CONNTRACK_CLOSE:

		LWIP_DEBUGF(NAT_DEBUG, ("%s: CLOSE\n", __func__));

		if (index == TCP_RST_SET
		    //&& test_bit(IPS_SEEN_REPLY_BIT, &conntrack->status)
		    && (pcb->status & TS_SEEN_REPLY)
		    && pcb->proto.TCP.last_index == TCP_SYN_SET
		    && ntohl(th->ackno) == pcb->proto.TCP.last_end) {
			/* RST sent to invalid SYN we had let trough
			 * SYN was in window then, tear down connection.
			 * We skip window checking, because packet might ACK
			 * segments we ignored in the SYN. */
			goto in_window;
		}
		/* Just fall trough */
	default:
		/* Keep compilers happy. */
		break;
	}

	if (!tcp_in_window(&pcb->proto.TCP, dir, index, skb, iph, th)) {

		LWIP_DEBUGF(NAT_DEBUG, ("%s: ! in window\n", __func__));

		write_unlock_bh(&tcp_lock);

		//return -NF_ACCEPT;
		* verdict = UF_ACCEPT;
		return -1;
	}
    in_window:
	/* From now on we have got in-window packets */	
	pcb->proto.TCP.last_index = index;

	pcb->proto.TCP.state = new_state;
	if (old_state != new_state 
	    && (new_state == TCP_CONNTRACK_FIN_WAIT || new_state == TCP_CONNTRACK_CLOSE))
		pcb->proto.TCP.seen[dir].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;

	timeout = pcb->proto.TCP.retrans >= ip_ct_tcp_max_retrans
		  && *tcp_timeouts[new_state] > ip_ct_tcp_timeout_max_retrans
		  ? ip_ct_tcp_timeout_max_retrans : *tcp_timeouts[new_state];

	write_unlock_bh(&tcp_lock);

	//if (!test_bit(IPS_SEEN_REPLY_BIT, &conntrack->status)) {
	if (!(TS_SEEN_REPLY & pcb->status)) {

		LWIP_DEBUGF(NAT_DEBUG, ("%s: ! SEEN REPLY \n", __func__));

		/* If only reply is a RST, we can consider ourselves not to
		   have an established connection: this is a fairly common
		   problem case, so we can delete the conntrack
		   immediately.  --RR */
		if (TCPH_FLAGS(th) & TCP_RST) {

			if (conn_remove_timer(pcb))
				conn_force_timeout(pcb);

//			return NF_ACCEPT;
			* verdict = UF_ACCEPT;
			return 1;

		}
///	} else if (!test_bit(IPS_ASSURED_BIT, &conntrack->status)
///		   && (old_state == TCP_CONNTRACK_SYN_RECV
///		       || old_state == TCP_CONNTRACK_ESTABLISHED)
//		   && new_state == TCP_CONNTRACK_ESTABLISHED) {
		/* Set ASSURED if we see see valid ack in ESTABLISHED 
		   after SYN_RECV or a valid answer for a picked up 
		   connection. */
///			set_bit(IPS_ASSURED_BIT, &conntrack->status);
	}

	LWIP_DEBUGF(NAT_DEBUG, ("%s: new timer %d\n", __func__, (unsigned int) timeout));

//	ip_ct_refresh_acct(conntrack, ctinfo, skb, timeout);
	conn_refresh_timer(timeout, pcb);

	//return NF_ACCEPT;
	* verdict = UF_ACCEPT;
	return 1;
}
 
int track_tcp_new2(struct nat_pcb *pcb, struct pbuf *p, void *iph, int iplen)
{
	enum tcp_conntrack new_state;
#ifdef DEBUGP_VARS
	//struct ip_ct_tcp_state *sender = &conntrack->proto.tcp.seen[0];
	//struct ip_ct_tcp_state *receiver = &conntrack->proto.tcp.seen[1];
	struct ip_ct_tcp_state *sender   = &pcb->proto.TCP.seen[0];
	struct ip_ct_tcp_state *receiver = &pcb->proto.TCP.seen[1];
#endif
	//int dataoff;
	//struct ip4_hdr *iph = (struct ip4_hdr *) skb->payload;
	//struct ip_hdr  *ip6hdr = (struct ip_hdr *) skb->payload;
	struct tcp_hdr *th;// _tcph;
	//if (IPH_V(ip6hdr) == 6)      dataoff = IP_HLEN;
	//else if (IPH_V(ip6hdr) == 4) dataoff = IPH4_HL(iph) * 4;

	//th = (struct tcp_hdr *) skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	th  = (struct tcp_hdr *) (((char*)iph)+iplen);

	/* Don't need lock here: this conntrack not in circulation yet */
	new_state = tcp_conntracks[0][get_conntrack_index(th)][TCP_CONNTRACK_NONE];

	/* Invalid: delete conntrack */
	if (new_state >= TCP_CONNTRACK_MAX) {
		return 0;
	}

	if (new_state == TCP_CONNTRACK_SYN_SENT) {

		LWIP_DEBUGF(NAT_DEBUG, ("%s: SYN SENT\n", __func__));

		/* SYN packet */
		//conntrack->proto.tcp.seen[0].td_end = segment_seq_plus_len(ntohl(th->seqno), skb->tot_len, iph, th);
		pcb->proto.TCP.seen[0].td_end    = segment_seq_plus_len(ntohl(th->seqno), p->tot_len, iph, th);
		pcb->proto.TCP.seen[0].td_maxwin = ntohs(th->wnd);

		if (pcb->proto.TCP.seen[0].td_maxwin == 0)
			pcb->proto.TCP.seen[0].td_maxwin = 1;

		pcb->proto.TCP.seen[0].td_maxend = pcb->proto.TCP.seen[0].td_end;

		tcp_options(p, iph, th, &pcb->proto.TCP.seen[0]);

		pcb->proto.TCP.seen[1].flags = 0;
		pcb->proto.TCP.seen[0].loose = 
		pcb->proto.TCP.seen[1].loose = 0;

	} else if (ip_ct_tcp_loose == 0) {
		/* Don't try to pick up connections. */
		return 0;
	} else {

		LWIP_DEBUGF(NAT_DEBUG, ("%s: TCP LOOSE\n", __func__));

		/*
		 * We are in the middle of a connection,
		 * its history is lost for us.
		 * Let's try to use the data from the packet.
		 */
		pcb->proto.TCP.seen[0].td_end = segment_seq_plus_len(ntohl(th->seqno), p->tot_len, iph, th);
		pcb->proto.TCP.seen[0].td_maxwin = ntohs(th->wnd);
		if (pcb->proto.TCP.seen[0].td_maxwin == 0)
			pcb->proto.TCP.seen[0].td_maxwin = 1;
		pcb->proto.TCP.seen[0].td_maxend = pcb->proto.TCP.seen[0].td_end + pcb->proto.TCP.seen[0].td_maxwin;
		pcb->proto.TCP.seen[0].td_scale  = 0;

		/* We assume SACK. Should we assume window scaling too? */
		pcb->proto.TCP.seen[0].flags =
		pcb->proto.TCP.seen[1].flags = IP_CT_TCP_FLAG_SACK_PERM;
		pcb->proto.TCP.seen[0].loose = 
		pcb->proto.TCP.seen[1].loose = ip_ct_tcp_loose;
	}
    
	pcb->proto.TCP.seen[1].td_end = 0;
	pcb->proto.TCP.seen[1].td_maxend = 0;
	pcb->proto.TCP.seen[1].td_maxwin = 1;
	pcb->proto.TCP.seen[1].td_scale = 0;      

	/* tcp_packet will set them */
	pcb->proto.TCP.state = TCP_CONNTRACK_NONE;
	pcb->proto.TCP.last_index = TCP_NONE_SET;

	LWIP_DEBUGF(NAT_DEBUG, ("%s: end\n", __func__));
	 
	return 1;
}

/*--------------------------------------------------------------------------*/

struct track_protocol  tcp_track = {
	.tuple   = track_tcp_tuple,
	.inverse = track_tcp_inverse,

	.error   = track_tcp_error,
	.new     = track_tcp_new2,
	.handle  = track_tcp_handle2, 

	.manip   = nat_tcp_manip,
	.nat_tuple_inverse = nat_tcp_tuple_inverse,
	.nat_free = nat_tcp_free
};


/* added by Diego Billi */
int ip_conntrack_protocol_tcp_lockinit(void)
{
	tcp_lock = sys_sem_new(1);
	return 0;
}

#endif 

