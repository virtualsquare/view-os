/*
 * Copyright (c) 2008 Renzo Davoli University of Bologna
 * 
 * Author: Renzo Davoli <renzo@cs.unibo.it>
 *
 */
#ifndef __LWIP_STACK_H__
#define __LWIP_STACK_H__

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/netif.h"
#include "lwip/ip_frag.h"
#include "lwip/tcpip.h"

struct raw_pcb;
struct tcp_seg; /* needs def */
struct tcp_hdr;
struct pbuf;
struct tcp_pcb;
struct ip_route_list; /* needs def */
struct ip_addr_list; /* needs def */
struct ip_reassbuf; /* needs def */
#define packet_pcb raw_pcb
struct udp_pcb;
struct tcp_pcb;  

/* IP_ROUTE_POOL_SIZE IP_ADDR_POOL_SIZE IP_REASS_POOL_SIZE need defs*/

struct stack {
	/* lwip-v6/src/core/raw.c */
	struct raw_pcb *raw_pcbs;
	/* lwip-v6/src/core/tcp_in.c */
	struct tcp_seg   inseg     ;
	struct tcp_hdr  *tcphdr    ;
	u32_t            seqno     ;
	u32_t            ackno     ;
	u8_t             flags     ;
	u16_t            tcplen    ;
	u8_t             recv_flags;
	struct pbuf     *recv_data ;
	struct tcp_pcb         *tcp_input_pcb;
	/* lwip-v6/src/core/netif.c */
	struct netif *netif_list;
	u16_t uniqueid;
	/* lwip-v6/src/core/ipv6/ip6.c */
	u16_t ip_id;
	/* lwip-v6/src/core/ipv6/ip6_route.c */
	struct ip_route_list *ip_route_head;
	/* lwip-v6/src/core/ipv6/ip6_frag.c */
	struct ip_reassbuf ip_reassembly_pools[IP_REASS_POOL_SIZE];
	/* lwip-v6/src/core/packet.c */
	u16_t active_pfpacket;
	struct packet_pcb *packet_pcbs;
	/* lwip-v6/src/core/udp.c */
	struct udp_pcb        *udp_pcbs;
	struct udp_pcb *pcb_cache;
	/* lwip-v6/src/core/tcp.c */
	u32_t tcp_ticks;
	union tcp_listen_pcbs_t tcp_listen_pcbs;
	struct tcp_pcb *tcp_active_pcbs;  /* List of all TCP PCBs that are in a */
	struct tcp_pcb *tcp_tw_pcbs;      /* List of all TCP PCBs in TIME-WAIT. */
	struct tcp_pcb *tcp_tmp_pcb;
	u8_t tcp_timer;
	/* lwip-v6/src/api/tcpip.c */
	sys_mbox_t stack_queue;
	sys_sem_t      tcpip_init_sem;
	tcpip_handler  tcpip_init_done;
	void *         tcpip_init_done_arg;
	sys_sem_t      tcpip_shutdown_sem;
	tcpip_handler  tcpip_shutdown_done;
	void *         tcpip_shutdown_done_arg;
	int tcpip_tcp_timer_active;
	/* lwip-v6/src/netif/loopif.c */
	int netif_num[NETIF_NUMIF];
};
#endif
