/*
 * @file
 *
 * Transmission Control Protocol, incoming traffic
 */

/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *
 *   Copyright 2004,2010,2011 Renzo Davoli University of Bologna - Italy
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
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */


/* tcp_input.c
 *
 * The input processing functions of TCP.
 *
 * These functions are generally called in the order (ip_input() ->) tcp_input() ->
 * tcp_process() -> tcp_receive() (-> application).
 *
 */



#include "lwip/def.h"
#include "lwip/opt.h"

#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/memp.h"

#include "lwip/inet.h"
#include "lwip/tcp.h"
#include "lwip/stack.h"

#include "lwip/stats.h"
#include "lwip/lwslirp.h"

#include "arch/perf.h"

#if LWIP_TCP

/* Forward declarations. */
static err_t tcp_process(struct tcp_pcb *pcb,struct pseudo_iphdr *piphdr);
static void tcp_receive(struct tcp_pcb *pcb);
static void tcp_parseopt(struct tcp_pcb *pcb);

static err_t tcp_listen_input(struct tcp_pcb_listen *pcb,struct pseudo_iphdr *piphdr
#ifdef LWSLIRP
		, struct netif *slirpif
#endif
		);

static err_t tcp_timewait_input(struct tcp_pcb *pcb);

#ifdef LWSLIRP
#define DROPWITHRESET(stack, tcphdr, piphdr) do {\
	tcp_rst(stack, 0, \
			ntohl((tcphdr)->seqno) + 1, (piphdr)->dest, (piphdr)->src, \
			ntohs((tcphdr)->dest), \
			ntohs((tcphdr)->src)); \
	return; \
} while(0)
#endif

/* tcp_input:
 *
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 */

	void
tcp_input(struct pbuf *p, struct ip_addr_list *inad, struct pseudo_iphdr *piphdr
#ifdef LWSLIRP
		, struct netif *slirpif
#endif
		)
{
	struct netif *netif = inad->netif;
	struct stack *stack = netif->stack;

	struct tcp_pcb *pcb, *prev;
	struct tcp_pcb_listen *lpcb;
	u8_t hdrlen;
	err_t err;



	/*struct netif *inp=inad->netif;*/

#if SO_REUSE
	struct tcp_pcb *pcb_temp;
	int reuse = 0;
	int reuse_port = 0;
#endif /* SO_REUSE */

	PERF_START;

	TCP_STATS_INC(tcp.recv);

	/*iphdr = p->payload; */
	/*tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);*/
	stack->tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + piphdr -> iphdrlen);

#if TCP_INPUT_DEBUG
	tcp_debug_print(stack->tcphdr);
#endif

	/* remove header from payload */
	/*if (pbuf_header(p, -((s16_t)(IPH_HL(iphdr) * 4))) || (p->tot_len < sizeof(struct tcp_hdr))) */
	if (pbuf_header(p, - piphdr -> iphdrlen)|| (p->tot_len < sizeof(struct tcp_hdr)))
	{
		/* drop short packets */
		LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: short packet (%u bytes) discarded\n", p->tot_len));
		TCP_STATS_INC(tcp.lenerr);
		TCP_STATS_INC(tcp.drop);
		pbuf_free(p);
		return;
	}

	/* Don't even process incoming broadcasts/multicasts. */
	/*if (ip_addr_ismulticast(&(iphdr->dest)) ||
		ip_addr_is_v4broadcast(&(iphdr->dest),&(inad->ipaddr),&(inad->netmask)) ||
		ip_addr_is_v4multicast(&(iphdr->dest))) */
	if (ip_addr_ismulticast(piphdr->dest) ||
			ip_addr_is_v4broadcast(piphdr->dest,&(inad->ipaddr),&(inad->netmask)) ||
			ip_addr_is_v4multicast(piphdr->dest))
	{
		pbuf_free(p);
		return;
	}

	/* Verify TCP checksum. */
	if (inet6_chksum_pseudo(p, piphdr->src,
				piphdr->dest,
				IP_PROTO_TCP, p->tot_len) != 0) {
		/*printf("+++++++ chksumv6 %x\n",inet6_chksum_pseudo(p, piphdr->src, piphdr->dest, IP_PROTO_TCP, p->tot_len));*/
		LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packet discarded due to failing checksum 0x%04x\n",
					inet6_chksum_pseudo(p, piphdr->src, piphdr->dest,
						IP_PROTO_TCP, p->tot_len)));
#if TCP_DEBUG
		tcp_debug_print(stack->tcphdr);
#endif /* TCP_DEBUG */
		TCP_STATS_INC(tcp.chkerr);
		TCP_STATS_INC(tcp.drop);


		pbuf_free(p);
		return;

	}

	/* Move the payload pointer in the pbuf so that it points to the
		 TCP data instead of the TCP header. */
	hdrlen = TCPH_HDRLEN(stack->tcphdr);
	pbuf_header(p, -(hdrlen * 4));

	/* Convert fields in TCP header to host byte order. */
	stack->tcphdr->src = ntohs(stack->tcphdr->src);
	stack->tcphdr->dest = ntohs(stack->tcphdr->dest);
	stack->seqno = stack->tcphdr->seqno = ntohl(stack->tcphdr->seqno);
	stack->ackno = stack->tcphdr->ackno = ntohl(stack->tcphdr->ackno);
	stack->tcphdr->wnd = ntohs(stack->tcphdr->wnd);

	stack->flags = TCPH_FLAGS(stack->tcphdr) & TCP_FLAGS;
	stack->tcplen = p->tot_len + ((stack->flags & TCP_FIN || stack->flags & TCP_SYN)? 1: 0);

	/* Demultiplex an incoming segment. First, we check if it is destined
		 for an active connection. */
	prev = NULL;

#if SO_REUSE
	pcb_temp = stack->tcp_active_pcbs;

again_1:

	/* Iterate through the TCP pcb list for a fully matching pcb */
	for(pcb = pcb_temp; pcb != NULL; pcb = pcb->next)
#else  /* SO_REUSE */
		for(pcb = stack->tcp_active_pcbs; pcb != NULL; pcb = pcb->next) 
#endif  /* SO_REUSE */
		{
			LWIP_ASSERT("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
			LWIP_ASSERT("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
			LWIP_ASSERT("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
#if 0
			fprintf(stderr, "ACTIVE %x %x %x %x:%d %x %x %x %x %d\n",
					pcb->local_ip.addr[0], pcb->local_ip.addr[1], pcb->local_ip.addr[2], pcb->local_ip.addr[3],
					pcb->local_port,
					pcb->remote_ip.addr[0], pcb->remote_ip.addr[1], pcb->remote_ip.addr[2], pcb->remote_ip.addr[3],
					pcb->remote_port, slirpif);
#endif

			if (pcb->remote_port == stack->tcphdr->src &&
					pcb->local_port   == stack->tcphdr->dest &&
					ip_addr_cmp(&(pcb->remote_ip), piphdr->src) &&
					ip_addr_cmp(&(pcb->local_ip), piphdr->dest)) {

#if SO_REUSE
				if(pcb->so_options & SOF_REUSEPORT) {
					if(reuse) {
						/* We processed one PCB already */
						LWIP_DEBUGF(TCP_INPUT_DEBUG,("tcp_input: second or later PCB and SOF_REUSEPORT set.\n"));
					} else {
						/* First PCB with this address */
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: first PCB and SOF_REUSEPORT set.\n"));
						reuse = 1;
					}

					reuse_port = 1; 
					p->ref++;

					/* We want to search on next socket after receiving */
					pcb_temp = pcb->next;

					LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: reference counter on PBUF set to %i\n", p->ref));
				} else  {
					if(reuse) {
						/* We processed one PCB already */
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: second or later PCB but SOF_REUSEPORT not set !\n"));
					}
				}
#endif /* SO_REUSE */

				/* Move this PCB to the front of the list so that subsequent
					 lookups will be faster (we exploit locality in TCP segment
					 arrivals). */
				LWIP_ASSERT("tcp_input: pcb->next != pcb (before cache)", pcb->next != pcb);
				if (prev != NULL) {
					prev->next = pcb->next;
					pcb->next = stack->tcp_active_pcbs;
					stack->tcp_active_pcbs = pcb;
				}
				LWIP_ASSERT("tcp_input: pcb->next != pcb (after cache)", pcb->next != pcb);
				break;
			}
			prev = pcb;
		}

	if (pcb == NULL) {
		/* If it did not go to an active connection, we check the connections
			 in the TIME-WAIT state. */

		for(pcb = stack->tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) {
			LWIP_ASSERT("tcp_input: TIME-WAIT pcb->state == TIME-WAIT", pcb->state == TIME_WAIT);
			if (pcb->remote_port == stack->tcphdr->src &&
					pcb->local_port == stack->tcphdr->dest &&
					ip_addr_cmp(&(pcb->remote_ip), piphdr->src) &&
					ip_addr_cmp(&(pcb->local_ip), piphdr->dest)) {
				/* We don't really care enough to move this PCB to the front
					 of the list since we are not very likely to receive that
					 many segments for connections in TIME-WAIT. */
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for TIME_WAITing connection.\n"));
				tcp_timewait_input(pcb);
				pbuf_free(p);
				return;
			}
		}

		/* Finally, if we still did not get a match, we check all PCBs that
			 are LISTENing for incoming connections. */
		prev = NULL;
		for(lpcb = stack->tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
#if 0
			fprintf(stderr, "LISTEN %x %x %x %x:%d %x %x %x %x %d %p\n",
					lpcb->local_ip.addr[0], lpcb->local_ip.addr[1], lpcb->local_ip.addr[2], lpcb->local_ip.addr[3],
					lpcb->local_port,
					lpcb->remote_ip.addr[0], lpcb->remote_ip.addr[1], lpcb->remote_ip.addr[2], lpcb->remote_ip.addr[3],
					lpcb->remote_port, slirpif);
#endif
			if (((
#ifdef LWSLIRP
							/* X1011: inaddr_any is for local interfaces only */
							slirpif == NULL &&
#endif
							ip_addr_isany(&(lpcb->local_ip))) ||
						ip_addr_cmp(&(lpcb->local_ip), piphdr->dest)) &&
					lpcb->local_port == stack->tcphdr->dest
#ifdef LWSLIRP
					/* RD1014 slirpif connections need remote port match! otherwise slirp misunderstands
						 all the connections to the same target host! */
					&& (!slirpif || lpcb->remote_port == stack->tcphdr->src)
#endif
					) {
				/* Move this PCB to the front of the list so that subsequent
					 lookups will be faster (we exploit locality in TCP segment
					 arrivals). */
				if (prev != NULL) {
					((struct tcp_pcb_listen *)prev)->next = lpcb->next;
					/* our successor is the remainder of the listening list */
					lpcb->next = stack->tcp_listen_pcbs.listen_pcbs;
					/* put this listening pcb at the head of the listening list */
					stack->tcp_listen_pcbs.listen_pcbs = lpcb;
				}

				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: packed for LISTENing connection, "));
#ifdef LWSLIRP
				if (slirpif && ip_addr_cmp(&(lpcb->remote_ip), piphdr->src) &&
						 lpcb->remote_port == stack->tcphdr->src) {
#if LWSLIRP_DEBUG
					slirp_debug_print_state(TCP_INPUT_DEBUG, (struct tcp_pcb *)lpcb );
#endif
					LWIP_DEBUGF(TCP_INPUT_DEBUG, ("\n"));
					/* If the socket is not configured (= -1) ... */
					if(lpcb->slirp_state & SS_NOFDREF) {
						/* There are two cases in which ->slirp_state == SS_NOFDREF:
						 * 1. The tcp pcb in new, and I try to connect its socket ->s with
						 *    the real world, so its ->s is == -1. 
						 * or
						 * 2. The connection of the socket ->s is already failed so
						 *    ->slirp_state has become SS_NOFDREF _but_ ->s its != -1 */
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: lpcb->slirp_fddata %p\n", lpcb->slirp_fddata));
						if(lpcb->slirp_fddata == NULL) {
							LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: lpcb->slirp = %p, so try to connect it.\n", lpcb->slirp_fddata));
							/* ... set up it and  try to connect the socket. */
							/*
							 * Haven't connected yet, save the current pbuf,
							 * and return 
							 */
							/* I restore the packet as it was before the call of tcp_input, 
							 * so: */
							/* 1. I restore the tcp header field in network order */
							stack->tcphdr->src = htons(stack->tcphdr->src);
							stack->tcphdr->dest = htons(stack->tcphdr->dest);
							stack->tcphdr->seqno = htonl(stack->tcphdr->seqno);
							stack->tcphdr->ackno = htonl(stack->tcphdr->ackno);
							stack->tcphdr->wnd = htons(stack->tcphdr->wnd);
							/* 2. I restore the payload pointer to include the IP e TCP header */
							pbuf_header(p, (TCPH_HDRLEN(stack->tcphdr) * 4) + piphdr->iphdrlen);

							/* 3. Save the packet */
							lpcb->slirp_m = p;

							if(slirp_tcp_fconnect(lpcb, ntohs(stack->tcphdr->dest), piphdr->dest, slirpif) == -1 && errno != EINPROGRESS) {

								/* Some errors (different from EINPROGRESS) happen */
								LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: socket connection to "
											"Internet failed, errno %d-%s\n", errno, strerror(errno)));
								if(errno == ECONNREFUSED) {
									/* abort the conncetion: ACK the SYN, send RST to refuse the connection */
									/* XXX NO! abort does not work on listen_tcp */
									DROPWITHRESET(stack, stack->tcphdr, piphdr);
									/* tcp_abort((struct tcp_pcb *) lpcb); */
								} else {
									enum icmp_dur_type code = ICMP_DUR_NET;
									if(errno == EHOSTUNREACH)
										code = ICMP_DUR_HOST;
									/* send host/net unreachable */
									icmp_dest_unreach(stack, p, code);
								}
								/* close the connection and free the packet */
								tcp_close((struct tcp_pcb *) lpcb);
								pbuf_free(p);
							} 

							/* I return without menage the incoming packet.
							 * I wait that the 3-way handshake teminates in the 
							 * real world connection and tcp_listen_input() will
							 * be call in slirp_select_pool if the connection was right setup*/
							return;
						} else { /* (->slirp_state & SS_NOFDREF && ->so != -1) */
							/* an error is occurred during connection */
							/* tcp_close((struct tcp_pcb *) lpcb); */
							/* tcp_abort((struct tcp_pcb *) lpcb);*/
							DROPWITHRESET(stack, stack->tcphdr, piphdr);
							tcp_close((struct tcp_pcb *) lpcb);
							pbuf_free(p);
						}
					} else {
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: lpcb->slirp = %p is connecting, ", lpcb->slirp_fddata));
#if LWSLIRP_DEBUG
						slirp_debug_print_state(TCP_INPUT_DEBUG, (struct tcp_pcb *)lpcb);
#endif
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("\n"));
						/* ...otherwise menage the incoming packet. It should be a SYN packet.*/
						if(tcp_listen_input(lpcb,piphdr,slirpif) != ERR_OK)
							DROPWITHRESET(stack, stack->tcphdr, piphdr);
						pbuf_free(p);

						/* Now that I have created a connected TCP pcb, I remove the 
						 * listen pcb from the list and I delete it. */
						TCP_RMV(&stack->tcp_listen_pcbs.listen_pcbs, lpcb);
						memp_free(MEMP_TCP_PCB_LISTEN, lpcb);
						return;
					}
				} else 
#endif /* LWSLIRP */
				{
					tcp_listen_input(lpcb,piphdr
#ifdef LWSLIRP
							,slirpif
#endif
							);
					pbuf_free(p);
					return;
				}
			}

			prev = (struct tcp_pcb *)lpcb;
		}
	}

#if TCP_INPUT_DEBUG
	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("+-+-+-+-+-+-+-+-+-+-+-+-+-+- tcp_input: flags "));
	tcp_debug_print_flags(TCPH_FLAGS(stack->tcphdr));
	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"));
#endif /* TCP_INPUT_DEBUG */

	if (pcb != NULL) {
		/* The incoming segment belongs to a connection. */
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
		tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */

		/* Set up a tcp_seg structure. */
		stack->inseg.next = NULL;
		stack->inseg.len = p->tot_len;
		stack->inseg.dataptr = p->payload;
		stack->inseg.p = p;
		stack->inseg.tcphdr = stack->tcphdr;

		stack->recv_data = NULL;
		stack->recv_flags = 0;

		stack->tcp_input_pcb = pcb;
		err = tcp_process(pcb,piphdr);
		stack->tcp_input_pcb = NULL;
		/* A return value of ERR_ABRT means that tcp_abort() was called
			 and that the pcb has been freed. If so, we don't do anything. */
		if (err != ERR_ABRT) {
			if (stack->recv_flags & TF_RESET) {
				/* TF_RESET means that the connection was reset by the other
					 end. We then call the error callback to inform the
					 application that the connection is dead before we
					 deallocate the PCB. */
				TCP_EVENT_ERR(pcb->errf, pcb->callback_arg, ERR_RST);
				tcp_pcb_remove(&stack->tcp_active_pcbs, pcb);
				memp_free(MEMP_TCP_PCB, pcb);
			} else if (stack->recv_flags & TF_CLOSED) {
				/* The connection has been closed and we will deallocate the
					 PCB. */
				tcp_pcb_remove(&stack->tcp_active_pcbs, pcb);
				memp_free(MEMP_TCP_PCB, pcb);
			} else {
				err = ERR_OK;
				/* If the application has registered a "sent" function to be
					 called when new send buffer space is available, we call it
					 now. */
				if (pcb->acked > 0) {
					TCP_EVENT_SENT(pcb, pcb->acked, err);
				}

				if (stack->recv_data != NULL) {
					/* Notify application that data has been received. */
					TCP_EVENT_RECV(pcb, stack->recv_data, ERR_OK, err);
				}

				/* If a FIN segment was received, we call the callback
					 function with a NULL buffer to indicate EOF. */
				if (stack->recv_flags & TF_GOT_FIN) {
					TCP_EVENT_RECV(pcb, NULL, ERR_OK, err);
				}
				/* If there were no errors, we try to send something out. */
				if (err == ERR_OK) {
					tcp_output(pcb);
				}
			}
		}

		/* We deallocate the incoming pbuf. If it was buffered by the
			 application, the application should have called pbuf_ref() to
			 increase the reference counter in the pbuf. If so, the buffer
			 isn't actually deallocated by the call to pbuf_free(), only the
			 reference count is decreased. */
		if (stack->inseg.p != NULL) pbuf_free(stack->inseg.p);
#if TCP_INPUT_DEBUG
#if TCP_DEBUG
		tcp_debug_print_state(pcb->state);
#endif /* TCP_DEBUG */
#endif /* TCP_INPUT_DEBUG */
#if SO_REUSE
		/* First socket should receive now */
		if(reuse_port) {
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: searching next PCB.\n"));
			reuse_port = 0;

			/* We are searching connected sockets */
			goto again_1;
		}
#endif /* SO_REUSE */

	} else {
#if SO_REUSE
		if(reuse) {
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: freeing PBUF with reference counter set to %i\n", p->ref));
			pbuf_free(p);
			goto end;
		}
#endif /* SO_REUSE */
#ifdef LWSLIRP
		if (slirpif) {
			struct tcp_pcb *tcp_pcb;
			struct tcp_pcb *ltcp_pcb;
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: no PCB match found\n"));

			/* XXX If a TCB does not exist, and the TCP_SYN flag is
			 * the only flag set, then create a session, mark it
			 * as if it was LISTENING, and continue... */
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("(flags & (TCP_SYN | TCP_FIN | "
						"TCP_RST | TCP_URG | TCP_ACK))(%d) != TCP_SYN (%d)=> %d\n",
						(stack->flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_URG | TCP_ACK)), TCP_SYN,
						(stack->flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_URG | TCP_ACK) != TCP_SYN)));

			if((stack->flags & (TCP_SYN | TCP_FIN | TCP_RST | TCP_URG | TCP_ACK)) != TCP_SYN) {
				DROPWITHRESET(stack, stack->tcphdr, piphdr);
				return;
			}
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: only TCP_SYN flag set, so i create a new pcb.\n"));

			/* I create a new tcp control block ...*/
			if((tcp_pcb = tcp_new(stack)) == NULL) {
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: creation of a new pcb failed.\n"));
				DROPWITHRESET(stack, stack->tcphdr, piphdr);
			}
			/* ... I set the reuse port option ...*/
			tcp_pcb->so_options |=  SOF_REUSEPORT;
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: tcp_pcb->so_options & SOF_REUSEPORT(%d) = %d, tcp_pcb = %p, tcp_pcb->slirp =%p\n",
						SOF_REUSEPORT, tcp_pcb->so_options & SOF_REUSEPORT, tcp_pcb, tcp_pcb->slirp_fddata));
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: new TCP pcb created = %p.\n", tcp_pcb));

			/* ... and i bind it to the destination address/port of the packet*/
			if(tcp_bind(tcp_pcb, piphdr->dest, stack->tcphdr->dest) != ERR_OK) {
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: tcp_bind() error.\n"));
				DROPWITHRESET(stack, stack->tcphdr, piphdr);
			}

			/* set the state of the connection to LISTEN */
			if((ltcp_pcb = tcp_listen(tcp_pcb)) == NULL){
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: setting pcb in LISTEN state failed.\n"));
				DROPWITHRESET(stack, stack->tcphdr, piphdr);
			}

			/* I register the callback function accept */
			tcp_accept(ltcp_pcb, slirp_tcp_accept);
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_input: after tcp_listen, tcp_pcb = %p.\n", tcp_pcb));

			ip_addr_set(&(ltcp_pcb->remote_ip), piphdr->src);
			ltcp_pcb->remote_port = stack->tcphdr->src;

			/* I go up, and search again in the TCP PCB, so now for this packet a pcb is
			 * found in the tcp_listen_pcbs list and is managed by the stack. */
			goto again_1;

		} else
#endif
		{
			/* If no matching PCB was found, send a TCP RST (reset) to the
				 sender. */
			LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_input: no PCB match found, resetting.\n"));
			if (!(TCPH_FLAGS(stack->tcphdr) & TCP_RST)) {
				TCP_STATS_INC(tcp.proterr);
				TCP_STATS_INC(tcp.drop);
				tcp_rst(stack, stack->ackno, stack->seqno + stack->tcplen,
						piphdr->dest, piphdr->src,
						stack->tcphdr->dest, stack->tcphdr->src);
			}
			pbuf_free(p);
		}
	}
#if SO_REUSE
end:
#endif /* SO_REUSE */
	LWIP_ASSERT("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
	PERF_STOP("tcp_input");
}

/* tcp_listen_input():
 *
 * Called by tcp_input() when a segment arrives for a listening
 * connection.
 */

	static err_t
tcp_listen_input(struct tcp_pcb_listen *pcb, struct pseudo_iphdr *piphdr
#ifdef LWSLIRP
		, struct netif *slirpif
#endif
		)
{
	struct stack *stack = pcb->stack;

	struct tcp_pcb *npcb;
	u32_t optdata;

	/* In the LISTEN state, we check for incoming SYN segments,
		 creates a new PCB, and responds with a SYN|ACK. */
	if (stack->flags & TCP_ACK) {
		/* For incoming segments with the ACK flag set, respond with a
			 RST. */
		LWIP_DEBUGF(TCP_RST_DEBUG, ("tcp_listen_input: ACK in LISTEN, sending reset\n"));
		tcp_rst(stack, 
				stack->ackno + 1, stack->seqno + stack->tcplen,
				piphdr->dest, piphdr->src,
				stack->tcphdr->dest, stack->tcphdr->src);
	} 
	else if (stack->flags & TCP_SYN) {
		LWIP_DEBUGF(TCP_DEBUG, ("TCP connection request %u -> %u.\n", stack->tcphdr->src, stack->tcphdr->dest));

		npcb = tcp_alloc(stack, pcb->prio);

		/* If a new PCB could not be created (probably due to lack of memory),
			 we don't do anything, but rely on the sender will retransmit the
			 SYN at a time when we have more memory available. */
		if (npcb == NULL) {
			LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: could not allocate PCB\n"));
			TCP_STATS_INC(tcp.memerr);
			return ERR_MEM;
		}
		/* Set up the new PCB. */
		npcb->stack = stack;

		ip_addr_set(&(npcb->local_ip), piphdr->dest);
		npcb->local_port = pcb->local_port;
		ip_addr_set(&(npcb->remote_ip), piphdr->src);
		npcb->remote_port = stack->tcphdr->src;
		npcb->state = SYN_RCVD;
		npcb->rcv_nxt = stack->seqno + 1;
		npcb->snd_wnd = stack->tcphdr->wnd;
		npcb->ssthresh = npcb->snd_wnd;
		npcb->snd_wl1 = stack->seqno - 1;/* initialise to seqno-1 to force window update */
		npcb->callback_arg = pcb->callback_arg;
#ifdef LWSLIRP
		if (slirpif) {
			npcb->slirp_fddata = pcb->slirp_fddata;
			npcb->slirp_state = pcb->slirp_state;
			LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: npcb->slirp = %p\n", npcb->slirp_fddata));
			/* I restore the ->s and the ->slirp_state fields, for new connections */
			pcb->slirp_fddata = NULL;
			pcb->slirp_state = SS_NOFDREF;
			LWIP_DEBUGF(TCP_DEBUG, ("tcp_listen_input: lpcb->slirp = %p\n", pcb->slirp_fddata));
		}
#endif /* LWSLIRP */

#if LWIP_CALLBACK_API
		npcb->accept = pcb->accept;
#ifdef LWSLIRP
		if (slirpif) {
			tcp_arg(npcb, NULL);
			tcp_recv(npcb, slirp_tcp_recv);
			tcp_sent(npcb, slirp_tcp_sent);
		}
#endif
#endif /* LWIP_CALLBACK_API */
		/* inherit socket options */
		npcb->so_options = pcb->so_options & (SOF_DEBUG|SOF_DONTROUTE|SOF_KEEPALIVE|SOF_OOBINLINE|SOF_LINGER);
#ifdef LWSLIRP
		if (slirpif)
			npcb->so_options |= SOF_REUSEPORT;
#endif

		/* Register the new PCB so that we can begin receiving segments
			 for it. */
		TCP_REG(&stack->tcp_active_pcbs, npcb);
#ifdef LWSLIRP
		slirp_tcp_update_listen2data(npcb);
#endif

		/* Parse any options in the SYN. */
		tcp_parseopt(npcb);

		/* Build an MSS option. */
		optdata = htonl(((u32_t)2 << 24) |
				((u32_t)4 << 16) |
				(((u32_t)npcb->mss / 256) << 8) |
				(npcb->mss & 255));
		/* Send a SYN|ACK together with the MSS option. */
		tcp_enqueue(npcb, NULL, 0, TCP_SYN | TCP_ACK, 0, (u8_t *)&optdata, 4);
		return tcp_output(npcb);
	}
	return ERR_OK;
}

/* tcp_timewait_input():
 *
 * Called by tcp_input() when a segment arrives for a connection in
 * TIME_WAIT.
 */

	static err_t
tcp_timewait_input(struct tcp_pcb *pcb)
{
	struct stack *stack = pcb->stack;

	if (TCP_SEQ_GT(stack->seqno + stack->tcplen, pcb->rcv_nxt)) {
		pcb->rcv_nxt = stack->seqno + stack->tcplen;
	}
	if (stack->tcplen > 0) {
		tcp_ack_now(pcb);
	}
	return tcp_output(pcb);
}

/* tcp_process
 *
 * Implements the TCP state machine. Called by tcp_input. In some
 * states tcp_receive() is called to receive data. The tcp_seg
 * argument will be freed by the caller (tcp_input()) unless the
 * recv_data pointer in the pcb is set.
 */

	static err_t
tcp_process(struct tcp_pcb *pcb,struct pseudo_iphdr *piphdr)
{
	struct stack *stack = pcb->stack;

	struct tcp_seg *rseg;
	u8_t acceptable = 0;
	err_t err;


	err = ERR_OK;

	/* Process incoming RST segments. */
	if (stack->flags & TCP_RST) {
		/* First, determine if the reset is acceptable. */
		if (pcb->state == SYN_SENT) {
			if (stack->ackno == pcb->snd_nxt) {
				acceptable = 1;
			}
		} else {
			/*if (TCP_SEQ_GEQ(seqno, pcb->rcv_nxt) &&
				TCP_SEQ_LEQ(seqno, pcb->rcv_nxt + pcb->rcv_wnd)) 
			 */
			if(TCP_SEQ_BETWEEN(stack->seqno, pcb->rcv_nxt, pcb->rcv_nxt+pcb->rcv_wnd))
			{
				acceptable = 1;
			}
		}

		if (acceptable) {
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: Connection RESET\n"));
			LWIP_ASSERT("tcp_input: pcb->state != CLOSED", pcb->state != CLOSED);
			stack->recv_flags = TF_RESET;
			pcb->flags &= ~TF_ACK_DELAY;
			return ERR_RST;
		} else {
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_process: unacceptable reset seqno %lu rcv_nxt %lu\n", stack->seqno, pcb->rcv_nxt));
			LWIP_DEBUGF(TCP_DEBUG, ("tcp_process: unacceptable reset seqno %lu rcv_nxt %lu\n", stack->seqno, pcb->rcv_nxt));
			return ERR_OK;
		}
	}

	/* Update the PCB (in)activity timer. */
	pcb->tmr = stack->tcp_ticks;
	pcb->keep_cnt = 0;

	/* Do different things depending on the TCP state. */
	switch (pcb->state) {
		case SYN_SENT:
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("SYN-SENT: ackno %lu pcb->snd_nxt %lu unacked %lu\n", stack->ackno, pcb->snd_nxt, ntohl(pcb->unacked->tcphdr->seqno)));
			/* received SYN ACK with expected sequence number? */
			if ((stack->flags & TCP_ACK) && (stack->flags & TCP_SYN)
					&& stack->ackno == ntohl(pcb->unacked->tcphdr->seqno) + 1) {
				pcb->snd_buf ++;
				pcb->rcv_nxt = stack->seqno + 1;
				pcb->lastack = stack->ackno;
				pcb->snd_wnd = stack->tcphdr->wnd;
				pcb->snd_wl1 = stack->seqno - 1; /* initialise to seqno - 1 to force window update */
				pcb->state = ESTABLISHED;
				pcb->cwnd = pcb->mss;
				--pcb->snd_queuelen;
				LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_process: SYN-SENT --queuelen %u\n", (unsigned int)pcb->snd_queuelen));
				rseg = pcb->unacked;
				pcb->unacked = rseg->next;
				tcp_seg_free(rseg);

				/* Parse any options in the SYNACK. */
				tcp_parseopt(pcb);

				/* Call the user specified function to call when sucessfully
				 * connected. */
				TCP_EVENT_CONNECTED(pcb, ERR_OK, err);
				tcp_ack(pcb);
			}
			/* received ACK? possibly a half-open connection */
			else if (stack->flags & TCP_ACK) {
				/* send a RST to bring the other side in a non-synchronized state. */

				tcp_rst(stack, stack->ackno, stack->seqno + stack->tcplen, piphdr->dest, piphdr->src,
						stack->tcphdr->dest, stack->tcphdr->src);
			}
			break;
		case SYN_RCVD:
			if (stack->flags & TCP_ACK &&
					!(stack->flags & TCP_RST)) {
				/* expected ACK number? */
				if(TCP_SEQ_BETWEEN(stack->ackno, pcb->lastack+1, pcb->snd_nxt)){
					pcb->state = ESTABLISHED;
					LWIP_DEBUGF(TCP_DEBUG, ("TCP connection established %u -> %u.\n", stack->inseg.tcphdr->src, stack->inseg.tcphdr->dest));
#if LWIP_CALLBACK_API
					LWIP_ASSERT("pcb->accept != NULL", pcb->accept != NULL);
#endif
					/* Call the accept function. */
					TCP_EVENT_ACCEPT(pcb, ERR_OK, err);
					if (err != ERR_OK) {
						/* If the accept function returns with an error, we abort
						 * the connection. */
						tcp_abort(pcb);
						return ERR_ABRT;
					}
					/* If there was any data contained within this ACK,
					 * we'd better pass it on to the application as well. */
					tcp_receive(pcb);
					pcb->cwnd = pcb->mss;
				}
				/* incorrect ACK number */
				else {
					/* send RST */
					tcp_rst(stack, stack->ackno, stack->seqno + stack->tcplen, piphdr->dest, piphdr->src,
							stack->tcphdr->dest, stack->tcphdr->src);
				}
			}
			break;
		case CLOSE_WAIT:
			/* FALLTHROUGH */
		case ESTABLISHED:
			tcp_receive(pcb);
			if (stack->flags & TCP_FIN) {
				tcp_ack_now(pcb);
				pcb->state = CLOSE_WAIT;
			}
			break;
		case FIN_WAIT_1:
			tcp_receive(pcb);
			if (stack->flags & TCP_FIN) {
				if (stack->flags & TCP_ACK && stack->ackno == pcb->snd_nxt) {
					LWIP_DEBUGF(TCP_DEBUG,
							("TCP connection closed %d -> %d.\n", stack->inseg.tcphdr->src, stack->inseg.tcphdr->dest));
					tcp_ack_now(pcb);
					tcp_pcb_purge(pcb);
					TCP_RMV(&stack->tcp_active_pcbs, pcb);
					pcb->state = TIME_WAIT;
					TCP_REG(&stack->tcp_tw_pcbs, pcb);
				} else {
					tcp_ack_now(pcb);
					pcb->state = CLOSING;
				}
			} else if (stack->flags & TCP_ACK && stack->ackno == pcb->snd_nxt) {
				pcb->state = FIN_WAIT_2;
			}
			break;
		case FIN_WAIT_2:
			tcp_receive(pcb);
			if (stack->flags & TCP_FIN) {
				LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed %u -> %u.\n", stack->inseg.tcphdr->src, stack->inseg.tcphdr->dest));
				tcp_ack_now(pcb);
				tcp_pcb_purge(pcb);
				TCP_RMV(&stack->tcp_active_pcbs, pcb);
				pcb->state = TIME_WAIT;
				TCP_REG(&stack->tcp_tw_pcbs, pcb);
			}
			break;
		case CLOSING:
			tcp_receive(pcb);
			if (stack->flags & TCP_ACK && stack->ackno == pcb->snd_nxt) {
				LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed %u -> %u.\n", stack->inseg.tcphdr->src, stack->inseg.tcphdr->dest));
				tcp_ack_now(pcb);
				tcp_pcb_purge(pcb);
				TCP_RMV(&stack->tcp_active_pcbs, pcb);
				pcb->state = TIME_WAIT;
				TCP_REG(&stack->tcp_tw_pcbs, pcb);
			}
			break;
		case LAST_ACK:
			tcp_receive(pcb);
			if (stack->flags & TCP_ACK && stack->ackno == pcb->snd_nxt) {
				LWIP_DEBUGF(TCP_DEBUG, ("TCP connection closed %u -> %u.\n", stack->inseg.tcphdr->src, stack->inseg.tcphdr->dest));
				pcb->state = CLOSED;
				stack->recv_flags = TF_CLOSED;
			}
			break;
		default:
			break;
	}

	return ERR_OK;
}

/* tcp_receive:
 *
 * Called by tcp_process. Checks if the given segment is an ACK for outstanding
 * data, and if so frees the memory of the buffered data. Next, is places the
 * segment on any of the receive queues (pcb->recved or pcb->ooseq). If the segment
 * is buffered, the pbuf is referenced by pbuf_ref so that it will not be freed until
 * i it has been removed from the buffer.
 *
 * If the incoming segment constitutes an ACK for a segment that was used for RTT
 * estimation, the RTT is estimated here as well.
 */

	static void
tcp_receive(struct tcp_pcb *pcb)
{
	struct stack *stack = pcb->stack;

	struct tcp_seg *next;
#if TCP_QUEUE_OOSEQ
	struct tcp_seg *prev, *cseg;
#endif
	struct pbuf *p;
	s32_t off;
	int m;
	u32_t right_wnd_edge;
	u16_t new_tot_len;


	if (stack->flags & TCP_ACK) {
		right_wnd_edge = pcb->snd_wnd + pcb->snd_wl1;

		/* Update window. */
		if (TCP_SEQ_LT(pcb->snd_wl1, stack->seqno) ||
				(pcb->snd_wl1 == stack->seqno && TCP_SEQ_LT(pcb->snd_wl2, stack->ackno)) ||
				(pcb->snd_wl2 == stack->ackno && stack->tcphdr->wnd > pcb->snd_wnd)) {
			pcb->snd_wnd = stack->tcphdr->wnd;
			pcb->snd_wl1 = stack->seqno;
			pcb->snd_wl2 = stack->ackno;
			LWIP_DEBUGF(TCP_WND_DEBUG, ("tcp_receive: window update %lu\n", pcb->snd_wnd));
#if TCP_WND_DEBUG
		} else {
			if (pcb->snd_wnd != stack->tcphdr->wnd) {
				LWIP_DEBUGF(TCP_WND_DEBUG, ("tcp_receive: no window update lastack %lu snd_max %lu ackno %lu wl1 %lu seqno %lu wl2 %lu\n",
							pcb->lastack, pcb->snd_max, stack->ackno, pcb->snd_wl1, stack->seqno, pcb->snd_wl2));
			}
#endif /* TCP_WND_DEBUG */
		}


		if (pcb->lastack == stack->ackno) {
			pcb->acked = 0;

			if (pcb->snd_wl1 + pcb->snd_wnd == right_wnd_edge){
				++pcb->dupacks;
				if (pcb->dupacks >= 3 && pcb->unacked != NULL) {
					if (!(pcb->flags & TF_INFR)) {
						/* This is fast retransmit. Retransmit the first unacked segment. */
						LWIP_DEBUGF(TCP_FR_DEBUG, ("tcp_receive: dupacks %u (%lu), fast retransmit %lu\n",
									(unsigned int)pcb->dupacks, pcb->lastack,
									ntohl(pcb->unacked->tcphdr->seqno)));
						tcp_rexmit(pcb);
						/* Set ssthresh to max (FlightSize / 2, 2*SMSS) */
						/*pcb->ssthresh = LWIP_MAX((pcb->snd_max -
							pcb->lastack) / 2,
							2 * pcb->mss);*/
						/* Set ssthresh to half of the minimum of the currenct cwnd and the advertised window */
						if(pcb->cwnd > pcb->snd_wnd)
							pcb->ssthresh = pcb->snd_wnd / 2;
						else
							pcb->ssthresh = pcb->cwnd / 2;

						pcb->cwnd = pcb->ssthresh + 3 * pcb->mss;
						pcb->flags |= TF_INFR;
					} else {
						/* Inflate the congestion window, but not if it means that
							 the value overflows. */
						if ((u16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
							pcb->cwnd += pcb->mss;
						}
					}
				}
			} else {
				LWIP_DEBUGF(TCP_FR_DEBUG, ("tcp_receive: dupack averted %lu %lu\n",
							pcb->snd_wl1 + pcb->snd_wnd, right_wnd_edge));
			}
		} else {
			/*if (TCP_SEQ_LT(pcb->lastack, ackno) &&
				TCP_SEQ_LEQ(ackno, pcb->snd_max))  */
			if(TCP_SEQ_BETWEEN(stack->ackno, pcb->lastack+1, pcb->snd_max))
			{
				/* We come here when the ACK acknowledges new data. */

				/* Reset the "IN Fast Retransmit" flag, since we are no longer
					 in fast retransmit. Also reset the congestion window to the
					 slow start threshold. */
				if (pcb->flags & TF_INFR) {
					pcb->flags &= ~TF_INFR;
					pcb->cwnd = pcb->ssthresh;
				}

				/* Reset the number of retransmissions. */
				pcb->nrtx = 0;

				/* Reset the retransmission time-out. */
				pcb->rto = (pcb->sa >> 3) + pcb->sv;

				/* Update the send buffer space. */
				pcb->acked = stack->ackno - pcb->lastack;

				/* FIX: Data split over odd boundaries */
				pcb->snd_buf += ((pcb->acked+1) & ~0x1); /* Even the send buffer */

				/* Reset the fast retransmit variables. */
				pcb->dupacks = 0;
				pcb->lastack = stack->ackno;

				/* Update the congestion control variables (cwnd and
					 ssthresh). */
				if (pcb->state >= ESTABLISHED) {
					if (pcb->cwnd < pcb->ssthresh) {
						if ((u16_t)(pcb->cwnd + pcb->mss) > pcb->cwnd) {
							pcb->cwnd += pcb->mss;
						}
						LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: slow start cwnd %u\n", pcb->cwnd));
					} else {
						u16_t new_cwnd = (pcb->cwnd + pcb->mss * pcb->mss / pcb->cwnd);
						if (new_cwnd > pcb->cwnd) {
							pcb->cwnd = new_cwnd;
						}
						LWIP_DEBUGF(TCP_CWND_DEBUG, ("tcp_receive: congestion avoidance cwnd %u\n", pcb->cwnd));
					}
				}
				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: ACK for %lu, unacked->seqno %lu:%lu\n",
							stack->ackno,
							pcb->unacked != NULL?
							ntohl(pcb->unacked->tcphdr->seqno): 0,
							pcb->unacked != NULL?
							ntohl(pcb->unacked->tcphdr->seqno) + TCP_TCPLEN(pcb->unacked): 0));

				/* Remove segment from the unacknowledged list if the incoming
					 ACK acknowlegdes them. */
				while (pcb->unacked != NULL &&
						TCP_SEQ_LEQ(ntohl(pcb->unacked->tcphdr->seqno) +
							TCP_TCPLEN(pcb->unacked), stack->ackno)) {
					LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %lu:%lu from pcb->unacked\n",
								ntohl(pcb->unacked->tcphdr->seqno),
								ntohl(pcb->unacked->tcphdr->seqno) +
								TCP_TCPLEN(pcb->unacked)));

					next = pcb->unacked;
					pcb->unacked = pcb->unacked->next;

					LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %u ... ", (unsigned int)pcb->snd_queuelen));
					pcb->snd_queuelen -= pbuf_clen(next->p);
					tcp_seg_free(next);

					LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%u (after freeing unacked)\n", (unsigned int)pcb->snd_queuelen));
					if (pcb->snd_queuelen != 0) {
						LWIP_ASSERT("tcp_receive: valid queue length", pcb->unacked != NULL ||
								pcb->unsent != NULL);
					}
				}
				pcb->polltmr = 0;
			}
		}
		/* We go through the ->unsent list to see if any of the segments
			 on the list are acknowledged by the ACK. This may seem
			 strange since an "unsent" segment shouldn't be acked. The
			 rationale is that lwIP puts all outstanding segments on the
			 ->unsent list after a retransmission, so these segments may
			 in fact have been sent once. */
		while (pcb->unsent != NULL &&
				/*TCP_SEQ_LEQ(ntohl(pcb->unsent->tcphdr->seqno) + TCP_TCPLEN(pcb->unsent), ackno) &&
					TCP_SEQ_LEQ(ackno, pcb->snd_max)*/
				TCP_SEQ_BETWEEN(stack->ackno, ntohl(pcb->unsent->tcphdr->seqno) + TCP_TCPLEN(pcb->unsent), pcb->snd_max)
				) {
			LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: removing %lu:%lu from pcb->unsent\n",
						ntohl(pcb->unsent->tcphdr->seqno), ntohl(pcb->unsent->tcphdr->seqno) +
						TCP_TCPLEN(pcb->unsent)));

			next = pcb->unsent;
			pcb->unsent = pcb->unsent->next;
			LWIP_DEBUGF(TCP_QLEN_DEBUG, ("tcp_receive: queuelen %u ... ", (unsigned int)pcb->snd_queuelen));
			pcb->snd_queuelen -= pbuf_clen(next->p);
			tcp_seg_free(next);
			LWIP_DEBUGF(TCP_QLEN_DEBUG, ("%u (after freeing unsent)\n", (unsigned int)pcb->snd_queuelen));
			if (pcb->snd_queuelen != 0) {
				LWIP_ASSERT("tcp_receive: valid queue length",
						pcb->unacked != NULL || pcb->unsent != NULL);
			}

			if (pcb->unsent != NULL) {
				pcb->snd_nxt = htonl(pcb->unsent->tcphdr->seqno);
			}
		}
		/* End of ACK for new data processing. */

		LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: pcb->rttest %ld rtseq %lu ackno %lu\n",
					pcb->rttest, pcb->rtseq, stack->ackno));

		/* RTT estimation calculations. This is done by checking if the
			 incoming segment acknowledges the segment we use to take a
			 round-trip time measurement. */
		if (pcb->rttest && TCP_SEQ_LT(pcb->rtseq, stack->ackno)) {
			m = stack->tcp_ticks - pcb->rttest;

			LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: experienced rtt %u ticks (%u msec).\n",
						m, m * TCP_SLOW_INTERVAL));

			/* This is taken directly from VJs original code in his paper */
			m = m - (pcb->sa >> 3);
			pcb->sa += m;
			if (m < 0) {
				m = -m;
			}
			m = m - (pcb->sv >> 2);
			pcb->sv += m;
			pcb->rto = (pcb->sa >> 3) + pcb->sv;

			LWIP_DEBUGF(TCP_RTO_DEBUG, ("tcp_receive: RTO %u (%u miliseconds)\n",
						pcb->rto, pcb->rto * TCP_SLOW_INTERVAL));

			pcb->rttest = 0;
		}
	}

	/* If the incoming segment contains data, we must process it
		 further. */
	if (stack->tcplen > 0) {
		/* This code basically does three things:

			 +) If the incoming segment contains data that is the next
			 in-sequence data, this data is passed to the application. This
			 might involve trimming the first edge of the data. The rcv_nxt
			 variable and the advertised window are adjusted.

			 +) If the incoming segment has data that is above the next
			 sequence number expected (->rcv_nxt), the segment is placed on
			 the ->ooseq queue. This is done by finding the appropriate
			 place in the ->ooseq queue (which is ordered by sequence
			 number) and trim the segment in both ends if needed. An
			 immediate ACK is sent to indicate that we received an
			 out-of-sequence segment.

			 +) Finally, we check if the first segment on the ->ooseq queue
			 now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
			 rcv_nxt > ooseq->seqno, we must trim the first edge of the
			 segment on ->ooseq before we adjust rcv_nxt. The data in the
			 segments that are now on sequence are chained onto the
			 incoming segment so that we only need to call the application
			 once.
		 */

		/* First, we check if we must trim the first edge. We have to do
			 this if the sequence number of the incoming segment is less
			 than rcv_nxt, and the sequence number plus the length of the
			 segment is larger than rcv_nxt. */
		/*    if (TCP_SEQ_LT(seqno, pcb->rcv_nxt)){
					if (TCP_SEQ_LT(pcb->rcv_nxt, seqno + tcplen)) */
		if(TCP_SEQ_BETWEEN(pcb->rcv_nxt, stack->seqno+1, stack->seqno+stack->tcplen-1))
			/* Trimming the first edge is done by pushing the payload
				 pointer in the pbuf downwards. This is somewhat tricky since
				 we do not want to discard the full contents of the pbuf up to
				 the new starting point of the data since we have to keep the
				 TCP header which is present in the first pbuf in the chain.

				 What is done is really quite a nasty hack: the first pbuf in
				 the pbuf chain is pointed to by inseg.p. Since we need to be
				 able to deallocate the whole pbuf, we cannot change this
				 inseg.p pointer to point to any of the later pbufs in the
				 chain. Instead, we point the ->payload pointer in the first
				 pbuf to data in one of the later pbufs. We also set the
				 inseg.data pointer to point to the right place. This way, the
				 ->p pointer will still point to the first pbuf, but the
				 ->p->payload pointer will point to data in another pbuf.

				 After we are done with adjusting the pbuf pointers we must
				 adjust the ->data pointer in the seg and the segment
				 length.*/

		{
			off = pcb->rcv_nxt - stack->seqno;
			p = stack->inseg.p;
			if (stack->inseg.p->len < off) {
				new_tot_len = stack->inseg.p->tot_len - off;
				while (p->len < off) {
					off -= p->len;
					/* KJM following line changed (with addition of new_tot_len var)
						 to fix bug #9076
						 inseg.p->tot_len -= p->len; */
					p->tot_len = new_tot_len;
					p->len = 0;
					p = p->next;
				}
				pbuf_header(p, -off);
			} else {
				pbuf_header(stack->inseg.p, -off);
			}
			/* KJM following line changed to use p->payload rather than inseg->p->payload
				 to fix bug #9076 */
			stack->inseg.dataptr = p->payload;
			stack->inseg.len -= pcb->rcv_nxt - stack->seqno;
			stack->inseg.tcphdr->seqno = stack->seqno = pcb->rcv_nxt;
		} else {
			if(TCP_SEQ_LT(stack->seqno, pcb->rcv_nxt)){
				/* the whole segment is < rcv_nxt */
				/* must be a duplicate of a packet that has already been correctly handled */

				LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: duplicate seqno %lu\n", stack->seqno));
				tcp_ack_now(pcb);
			}
		}

		/* The sequence number must be within the window (above rcv_nxt
			 and below rcv_nxt + rcv_wnd) in order to be further
			 processed. */
		/*if (TCP_SEQ_GEQ(seqno, pcb->rcv_nxt) &&
			TCP_SEQ_LT(seqno, pcb->rcv_nxt + pcb->rcv_wnd))*/
		if(TCP_SEQ_BETWEEN(stack->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd - 1))
		{
			if (pcb->rcv_nxt == stack->seqno) {
				/* The incoming segment is the next in sequence. We check if
					 we have to trim the end of the segment and update rcv_nxt
					 and pass the data to the application. */
#if TCP_QUEUE_OOSEQ
				if (pcb->ooseq != NULL &&
						TCP_SEQ_LEQ(pcb->ooseq->tcphdr->seqno, stack->seqno + stack->inseg.len)) {
					/* We have to trim the second edge of the incoming
						 segment. */
					stack->inseg.len = pcb->ooseq->tcphdr->seqno - stack->seqno;
					pbuf_realloc(stack->inseg.p, stack->inseg.len);
				}
#endif /* TCP_QUEUE_OOSEQ */

				stack->tcplen = TCP_TCPLEN(&stack->inseg);

				pcb->rcv_nxt += stack->tcplen;

				/* Update the receiver's (our) window. */
				if (pcb->rcv_wnd < stack->tcplen) {
					pcb->rcv_wnd = 0;
				} else {
					pcb->rcv_wnd -= stack->tcplen;
				}

				/* If there is data in the segment, we make preparations to
					 pass this up to the application. The ->recv_data variable
					 is used for holding the pbuf that goes to the
					 application. The code for reassembling out-of-sequence data
					 chains its data on this pbuf as well.

					 If the segment was a FIN, we set the TF_GOT_FIN flag that will
					 be used to indicate to the application that the remote side has
					 closed its end of the connection. */
				if (stack->inseg.p->tot_len > 0) {
					stack->recv_data = stack->inseg.p;
					/* Since this pbuf now is the responsibility of the
						 application, we delete our reference to it so that we won't
						 (mistakingly) deallocate it. */
					stack->inseg.p = NULL;
				}
				if (TCPH_FLAGS(stack->inseg.tcphdr) & TCP_FIN) {
					LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: received FIN.\n"));
					stack->recv_flags = TF_GOT_FIN;
				}

#if TCP_QUEUE_OOSEQ
				/* We now check if we have segments on the ->ooseq queue that
					 is now in sequence. */
				while (pcb->ooseq != NULL &&
						pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt) {

					cseg = pcb->ooseq;
					stack->seqno = pcb->ooseq->tcphdr->seqno;

					pcb->rcv_nxt += TCP_TCPLEN(cseg);
					if (pcb->rcv_wnd < TCP_TCPLEN(cseg)) {
						pcb->rcv_wnd = 0;
					} else {
						pcb->rcv_wnd -= TCP_TCPLEN(cseg);
					}
					if (cseg->p->tot_len > 0) {
						/* Chain this pbuf onto the pbuf that we will pass to
							 the application. */
						if (stack->recv_data) {
							pbuf_cat(stack->recv_data, cseg->p);
						} else {
							stack->recv_data = cseg->p;
						}
						cseg->p = NULL;
					}
					if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
						LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_receive: dequeued FIN.\n"));
						stack->recv_flags = TF_GOT_FIN;
					}

					pcb->ooseq = cseg->next;
					tcp_seg_free(cseg);
				}
#endif /* TCP_QUEUE_OOSEQ */


				/* Acknowledge the segment(s). */
				tcp_ack(pcb);

			} else {
				/* We get here if the incoming segment is out-of-sequence. */
				tcp_ack_now(pcb);
#if TCP_QUEUE_OOSEQ
				/* We queue the segment on the ->ooseq queue. */
				if (pcb->ooseq == NULL) {
					pcb->ooseq = tcp_seg_copy(&stack->inseg);
				} else {
					/* If the queue is not empty, we walk through the queue and
						 try to find a place where the sequence number of the
						 incoming segment is between the sequence numbers of the
						 previous and the next segment on the ->ooseq queue. That is
						 the place where we put the incoming segment. If needed, we
						 trim the second edges of the previous and the incoming
						 segment so that it will fit into the sequence.

						 If the incoming segment has the same sequence number as a
						 segment on the ->ooseq queue, we discard the segment that
						 contains less data. */

					prev = NULL;
					for(next = pcb->ooseq; next != NULL; next = next->next) {
						if (stack->seqno == next->tcphdr->seqno) {
							/* The sequence number of the incoming segment is the
								 same as the sequence number of the segment on
								 ->ooseq. We check the lengths to see which one to
								 discard. */
							if (stack->inseg.len > next->len) {
								/* The incoming segment is larger than the old
									 segment. We replace the old segment with the new
									 one. */
								cseg = tcp_seg_copy(&stack->inseg);
								if (cseg != NULL) {
									cseg->next = next->next;
									if (prev != NULL) {
										prev->next = cseg;
									} else {
										pcb->ooseq = cseg;
									}
								}
								break;
							} else {
								/* Either the lenghts are the same or the incoming
									 segment was smaller than the old one; in either
									 case, we ditch the incoming segment. */
								break;
							}
						} else {
							if (prev == NULL) {
								if (TCP_SEQ_LT(stack->seqno, next->tcphdr->seqno)) {
									/* The sequence number of the incoming segment is lower
										 than the sequence number of the first segment on the
										 queue. We put the incoming segment first on the
										 queue. */

									if (TCP_SEQ_GT(stack->seqno + stack->inseg.len, next->tcphdr->seqno)) {
										/* We need to trim the incoming segment. */
										stack->inseg.len = next->tcphdr->seqno - stack->seqno;
										pbuf_realloc(stack->inseg.p, stack->inseg.len);
									}
									cseg = tcp_seg_copy(&stack->inseg);
									if (cseg != NULL) {
										cseg->next = next;
										pcb->ooseq = cseg;
									}
									break;
								}
							} else 
								/*if (TCP_SEQ_LT(prev->tcphdr->seqno, seqno) &&
									TCP_SEQ_LT(seqno, next->tcphdr->seqno)) */
								if(TCP_SEQ_BETWEEN(stack->seqno, prev->tcphdr->seqno+1, next->tcphdr->seqno-1))
									/* The sequence number of the incoming segment is in
										 between the sequence numbers of the previous and
										 the next segment on ->ooseq. We trim and insert the
										 incoming segment and trim the previous segment, if
										 needed. */
								{
									if (TCP_SEQ_GT(stack->seqno + stack->inseg.len, next->tcphdr->seqno)) {
										/* We need to trim the incoming segment. */
										stack->inseg.len = next->tcphdr->seqno - stack->seqno;
										pbuf_realloc(stack->inseg.p, stack->inseg.len);
									}

									cseg = tcp_seg_copy(&stack->inseg);
									if (cseg != NULL) {
										cseg->next = next;
										prev->next = cseg;
										if (TCP_SEQ_GT(prev->tcphdr->seqno + prev->len, stack->seqno)) {
											/* We need to trim the prev segment. */
											prev->len = stack->seqno - prev->tcphdr->seqno;
											pbuf_realloc(prev->p, prev->len);
										}
									}
									break;
								}
							/* If the "next" segment is the last segment on the
								 ooseq queue, we add the incoming segment to the end
								 of the list. */
							if (next->next == NULL &&
									TCP_SEQ_GT(stack->seqno, next->tcphdr->seqno)) {
								next->next = tcp_seg_copy(&stack->inseg);
								if (next->next != NULL) {
									if (TCP_SEQ_GT(next->tcphdr->seqno + next->len, stack->seqno)) {
										/* We need to trim the last segment. */
										next->len = stack->seqno - next->tcphdr->seqno;
										pbuf_realloc(next->p, next->len);
									}
								}
								break;
							}
						}
						prev = next;
					}
				}
#endif /* TCP_QUEUE_OOSEQ */

			}
		} else {
			/*if (TCP_SEQ_GT(pcb->rcv_nxt, seqno) ||
				TCP_SEQ_GEQ(seqno, pcb->rcv_nxt + pcb->rcv_wnd)) */
			if(!TCP_SEQ_BETWEEN(stack->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd-1))
			{
				tcp_ack_now(pcb);
			}
		}
	} else {
		/* Segments with length 0 is taken care of here. Segments that
			 fall out of the window are ACKed. */
		/*if (TCP_SEQ_GT(pcb->rcv_nxt, seqno) ||
			TCP_SEQ_GEQ(seqno, pcb->rcv_nxt + pcb->rcv_wnd)) */
		if(!TCP_SEQ_BETWEEN(stack->seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd-1))
		{
			tcp_ack_now(pcb);
		}
	}
}

/*
 * tcp_parseopt:
 *
 * Parses the options contained in the incoming segment. (Code taken
 * from uIP with only small changes.)
 *
 */

	static void
tcp_parseopt(struct tcp_pcb *pcb)
{
	struct stack *stack = pcb->stack;

	u8_t c;
	u8_t *opts, opt;
	u16_t mss;

	opts = (u8_t *)stack->tcphdr + TCP_HLEN;

	/* Parse the TCP MSS option, if present. */
	if(TCPH_HDRLEN(stack->tcphdr) > 0x5) {
		for(c = 0; c < (TCPH_HDRLEN(stack->tcphdr) - 5) << 2 ;) {
			opt = opts[c];
			if (opt == 0x00) {
				/* End of options. */
				break;
			} else if (opt == 0x01) {
				++c;
				/* NOP option. */
			} else if (opt == 0x02 &&
					opts[c + 1] == 0x04) {
				/* An MSS option with the right option length. */
				mss = (opts[c + 2] << 8) | opts[c + 3];
				pcb->mss = mss > TCP_MSS? TCP_MSS: mss;

				/* And we are done processing options. */
				break;
			} else {
				if (opts[c + 1] == 0) {
					/* If the length field is zero, the options are malformed
						 and we don't process them further. */
					break;
				}
				/* All other options have a length field, so that we easily
					 can skip past them. */
				c += opts[c + 1];
			}
		}
	}
}
#endif /* LWIP_TCP */


