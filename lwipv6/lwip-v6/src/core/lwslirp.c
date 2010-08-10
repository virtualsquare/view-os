/*   This is part of Slirpvde6
 *   Developed for the VDE project
 *   Virtual Distributed Ethernet
 *   
 *   Copyright 2010 Renzo Davoli
 *   based on a previous work by Andrea Forni 2005
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

#include "lwip/opt.h"
#include "lwip/lwslirp.h"

#ifdef LWSLIRP
#include "lwip/mem.h"
#include "lwip/ip_addr.h"
#include "lwip/debug.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "lwip/stack.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>

/* Local function */
static void slirp_isfconnecting(struct tcp_pcb *pcb);
static void slirp_isfconnected(struct tcp_pcb *pcb);
static void slirp_fcantrcvmore(struct tcp_pcb *pcb, int posfd);
static void slirp_fcantsendmore(struct tcp_pcb *pcb, int posfd);
static void slirp_fd_nonblock(int fd);
#if LWSLIRP_DEBUG
void slirp_debug_print_state(int debk, struct tcp_pcb *pcb);
#else
#define slirp_debug_print_state(A,B) 
#endif

/* The function gets the pcb of the connection, and the version of IP protocolo (4 or 6)
 * and it returns the right destination IP address.
 *
 * NOTE: the function works both with UDP and TCP pcb, because it only use
 * ->local_ip field that is present in both pcb.*/
static struct ip_addr *slirp_get_destaddr(struct udp_pcb *pcb, unsigned char version) {
	struct ip_addr netmask, netmask6, *remote_addr;
	int last_byte_mask;

#if 0
	IP6_ADDR(&netmask, 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xff00);
	IP6_ADDR(&netmask6, 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xfff0);

	/* I control if it's one of our IPv4 or IPv6 addresses */
	if( (version == 4 && ip_addr_maskcmp(&pcb->local_ip, &special_addr, &netmask)) ||
			(version == 6 && ip_addr_maskcmp(&pcb->local_ip, &special_addr6, &netmask6)) ) {

		/* get the right mask based on IP version*/
		if(version == 6)
			last_byte_mask = 0x000000f;
		else
			last_byte_mask = 0x00000ff;

		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_get_destaddr: it's an our address, (htonl((pcb->local_ip).addr[3]) & %d) = %d\n",
					last_byte_mask, (htonl((pcb->local_ip).addr[3]) & last_byte_mask)));

		switch((htonl((pcb->local_ip).addr[3]) & last_byte_mask)) {
			case CTL_DNS:
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_get_destaddr: I'l send to DNS address: "));
				if(version == 4 && ip_addr_isany(&dns_addr)) {
					/* There is no IPv4 dns address, so I use IPv6 DNS addess*/
					remote_addr = &dns_addr6;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("its IPv4 but no IPv4 DNS exists, so I use IPv6 address\n"));
				} else if(version == 6 && ip_addr_isany(&dns_addr6)) {
					/* There is no IPv6 dns address, so I use IPv4 DNS addess*/
					remote_addr = &dns_addr;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("its IPv6 but no IPv6 DNS exists, so I use IPv4 address\n"));
				} else if(version == 4) {
					/* IPv4 DNS exists */
					remote_addr = &dns_addr;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("its IPv4 and I use IPv4 DNS address\n"));
				} else {
					/* IPv6 DNS exists */
					remote_addr = &dns_addr6;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("its IPv6 and I use IPv6 DNS address\n"));
				}

				break;
			case CTL_ALIAS:
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_get_destaddr: I'l send to ALIAS address and "));
			default:
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("to DEFAULT address: "));
				if(version == 4 ) {
					remote_addr = &loopback_addr;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("IPv4 loopback\n"));
				} else {
					remote_addr = &loopback_addr6;
					LWIP_DEBUGF(LWSLIRP_DEBUG, ("IPv6 loopback\n"));
				}
				break;
		}
	} else 
#endif
	{
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_sendto: it's not one of our addresses\n"));
		remote_addr = &pcb->local_ip;
	}

	return remote_addr;
}

/* TCP ****************************************************************************************/

/* This callback function is called when the TCP state goes from
 * SYN_RCVD to ESTABLISHED and it changes the socket state to
 * SS_ISFCONNECTED */
err_t slirp_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_accept: I change the state of socket %d from ", pcb->slirp_posfd));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);

	slirp_isfconnected(pcb);

	LWIP_DEBUGF(LWSLIRP_DEBUG, (" to "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));

	return ERR_OK;
}

/* This callback function is called when the TCP state goes from
 * SYN_SENT to ESTABLISHED and it changes the socket state to
 * SS_ISFCONNECTED */
err_t slirp_tcp_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_connected: I change the state of socket %d from ", pcb->slirp_posfd));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);

	slirp_isfconnected(pcb);
	slirp_tcp_update_listen2data(pcb);

	LWIP_DEBUGF(LWSLIRP_DEBUG, (" to "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
							  
	return ERR_OK;
}

/* This callback function is called when (in-sequence) data has arrived
 * in the TCP buffer of "pcb". These data, contained in pbuf "p" are
 * added to the pcb->slirp_recvbuf, that is the buffer where the socket
 * takes the data to send.*/
err_t slirp_tcp_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_recv: pbuf p (%p)", p));
#if LWSLIRP_DEBUG
	if(p != NULL)
		LWIP_DEBUGF(LWSLIRP_DEBUG, (", I have receved %d bytes "
					"(p->tot_len = %d)\n", p->len, p->tot_len));
	else
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
#endif /* LWSLIRP_DEBUG */

	if(p == NULL) {
		/* p == NULL, FIN segment received, so p == NULL indicate EOF */
		/* I don't do anything. I could call close(pcb->slirp_posfd), I don't do it,
		 * because if a FIN segment was received, the stack will call some
		 * close function that will call tcp_pcb_purge() which will close
		 * the socket. */
		return ERR_OK;
	} /* Else all ok!*/

	tcp_recved(pcb, p->tot_len);

	/* Concatenate the new pbuf p at the end of pcb->slirp_recvbuf */

	/* If the buffer is null, p become the head of it ...*/
	netif_slirp_events(pcb) |= POLLOUT;
	if(pcb->slirp_recvbuf == NULL) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_recv: ->slirp_recvbuf == "
					"NULL, so  p (%p) become the head of it\n", p));
		pcb->slirp_recvbuf = p;
	} else {
		/*... otherwise I concatenate p at the end of the buffer*/
		pbuf_cat(pcb->slirp_recvbuf, p);
	}

	return ERR_OK;
}

/* Read data from a slirp interface */
static int slirp_read (struct tcp_pcb *pcb, int posfd) {
	int ret, n;
	err_t res;
	char *buf;
	struct stack *stack = pcb->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);

	/* I get the number of bytes I can read from the read buffer */
	ioctl(slirp_fd, FIONREAD, &n);

	/* I test if there is enough room in the send queue of the TCP pcb */
	if( n > tcp_sndbuf(pcb)) {
		/* I try to empty the send buffer and try again */
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: no enought room in the send buffer, I can store "
					"%d bytes, but I have to read %d bytes. I try to empty the buffer.\n", tcp_sndbuf(pcb), n));
		tcp_output(pcb);
		if(n > tcp_sndbuf(pcb)) {
			/* I don't read nothing and I wait until there is more room */
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: I have tried to empty the send buffer, "));
			if(( n = tcp_sndbuf(pcb) ) == 0) {
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("but the free space is equal to %d, so I return without reading.\n",
							tcp_sndbuf(pcb)));
				return -1;
			}
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("but I have only %d bytes of free space when I need "
						"of %d bytes of space so I read only %d bytes.\n", tcp_sndbuf(pcb), n, tcp_sndbuf(pcb)));
		}
	}

	/* There is room for store the read data, so I read it */
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: I can read %d bytes, and I have read ", n));

	buf = mem_malloc(n);

	ret = read(slirp_fd, buf, n);

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("%d bytes\n", ret));
	if(ret <= 0) {
		if(ret < 0 && (errno == EINTR || errno == EAGAIN)) {
			mem_free(buf);
			return 0;
		} else {
			/* ret = 0, So */
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: disconnected, ret = %d, errno = %d-%s\n", ret, errno,strerror(errno)));
			slirp_fcantrcvmore(pcb, posfd);
			mem_free(buf);
			tcp_close(pcb);
			return -1;
		}
	}
	/* Now I enqueue the data, passing them to tcp_write().
	 * I know, from the previous control, that there is enough room 
	 * to store the read data, but a memory error can occur and so I
	 * close the connection. */
	res = tcp_write(pcb, buf, n, 1);
	if(res == ERR_MEM) {
		/* I close the connection */
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: error memory, I close the connection.\n"));
		mem_free(buf);
		tcp_close(pcb);
		return -1;
	}

	/* free the buffer */
	mem_free(buf);
	return ret;
}

/* discard data from a slirp interface when the interface is down */
static void slirp_discard_input(struct tcp_pcb *pcb)
{
	struct stack *stack = pcb->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);
	int n;
	char *buf;

	/* I get the number of bytes I can read from the read buffer */
	ioctl(slirp_fd, FIONREAD, &n);

	buf = mem_malloc(n);
	if (buf) {
		read(slirp_fd, buf, n);
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_read: Interface is down: %d bytes discarded ", n));
		mem_free(buf);
	}
}

/* write data to a slirp interface */
static int slirp_write(struct tcp_pcb *pcb, int posfd, struct netif *netif)
{
	int ret, total_ret = 0;
	struct pbuf *p;
	struct stack *stack = pcb->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);

	netif_slirp_events(pcb) &= ~POLLOUT;
	assert(pcb->slirp_recvbuf != NULL);
	/*
	if (pcb->slirp_recvbuf == NULL) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: ->slirp_recvbuf = NULL!!!!!!!!!!!!!!!!!!!!!\n"));
		return 0;
	}*/

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: ->slirp_recvbuf = %p, total lenght of recv "
				"queue = %d.\n", pcb->slirp_recvbuf, pcb->slirp_recvbuf->tot_len));

	p = pcb->slirp_recvbuf;
	while(p != NULL) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: Try to send (write) %d bytes of pbuf %p. (totlen = %d)\n", p->len, p, p->tot_len));

		if (netif->flags & NETIF_FLAG_UP) {
			ret = write(slirp_fd, p->payload, p->len);
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: write %d of %d bytes of pbuf %p\n", ret, p->len, p));
		} else {
			ret = p->len;
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: Interface is down: %d bytes discarded\n", ret));
		}

		/* This should never happen, but people tell me it does *shrug* */
		if (ret < 0 && (errno == EAGAIN || errno == EINTR))
			return 0;

		if(ret <= 0) {
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: disconnected, ret = %d, errno = %d-%s\n", ret, errno,strerror(errno)));
			slirp_fcantsendmore(pcb, posfd);
			tcp_close(pcb);
			return -1;
		}

		/* no error, I control how much I have written */
		if(ret == p->len) {
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: ret (%d) == p->len (%d), so "
						"I remove p (%p)  from the list [p->ref = %d].\n", ret, p->len, p, p->ref));

			/* I have send all the pcb, so I remove it from the list */

			pbuf_ref(p->next);
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: after pbuf_ref(%p), p->next->ref = %d\n", p->next, p->next == NULL ? 0:p->next->ref));
			pcb->slirp_recvbuf = pbuf_dechain(p);

			pbuf_free(p);

			p = pcb->slirp_recvbuf;
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: after pbuf_dechain, next "
						"pbuf will be p = %p", p));
#if LWSLIRP_DEBUG
			if(p != NULL)
				LWIP_DEBUGF(LWSLIRP_DEBUG, (", p->len = %d, p->tot_len = %d\n", p->len, p->tot_len));
			else
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
#endif /* LWSLIRP_DEBUG */


			if(p == NULL) {
				/* no more pbuf */
				total_ret += ret;
				return total_ret;
			}

			total_ret += ret;

		} else if (ret < p->len ) {
			/* I have send not all the pcb payload, so I adjust the payload pointer
			 * to point to the data unsent. */
			netif_slirp_events(pcb) |= POLLOUT;
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: ret (%d) < p->len (%d), so "
						"I adjust the payload of p (%p)  from "
						"%x I add (%d)\n", ret, p->len, p, p->payload, ret ));
			pbuf_header(p, ret);
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("%x(%d).\n", p->payload, p->payload));
			/* I cannot send more, so I exit from the while */
			break;
		} else {
			/* ret > p -> len : It's impossible! */
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_write: ret (%d) > p->len (%d): Impossible!\n", ret, p->len));
			assert(ret <= p->len);
		}
	}

	/* if p == NULL or ret < p->len I have not added the last ret to total_ret, so I do it now. */
	total_ret += ret;

	return total_ret;
}

/*
 * Various session state calls
 */
static void slirp_isfconnecting(struct tcp_pcb *pcb)
{
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_isfconnecting: before changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));

	pcb->slirp_state &= ~(SS_NOFDREF|SS_ISFCONNECTED|SS_FCANTRCVMORE|
			SS_FCANTSENDMORE|SS_FWDRAIN);
	pcb->slirp_state |= SS_ISFCONNECTING; /* Clobber other states */

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_isfconnecting: after changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
}

static void slirp_isfconnected(struct tcp_pcb *pcb)
{
	pcb->slirp_state &= ~(SS_ISFCONNECTING|SS_FWDRAIN|SS_NOFDREF);
	pcb->slirp_state |= SS_ISFCONNECTED;
}

static void slirp_fcantrcvmore(struct tcp_pcb *pcb, int posfd)
{
	struct stack *stack = pcb->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_isfcantrcvmore: SHUT_RD = %d\n", SHUT_RD));
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_isfcantrcvmore: before changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));

	/* if there is no reference of the fd, close this side of the socket connection,
	 * so that all the incoming packet will be discarded and remove the socket from the 
	 * write fd set*/
	if (!(pcb->slirp_state & SS_NOFDREF)) {
		shutdown(slirp_fd, SHUT_RD); /* SHUT_RD: further receptions  will  be  disallowed */
		stack->netif_pfd[posfd].revents &= ~POLLOUT;
	}

	pcb->slirp_state &= ~(SS_ISFCONNECTING);

	/* If the socket cannnot send data, remove the fd reference, otherwise
	 * set the state to SS_FCANTRCVMORE so that it cannot receive other data. */
	if (pcb->slirp_state & SS_FCANTSENDMORE)
		pcb->slirp_state = SS_NOFDREF; /* Don't select it */ /* XXX close() here as well? */
	else
		pcb->slirp_state |= SS_FCANTRCVMORE;

	LWIP_DEBUGF(LWSLIRP_DEBUG, (" after changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
}

static void slirp_fcantsendmore(struct tcp_pcb *pcb, int posfd)
{
	struct stack *stack = pcb->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_fcantsendmore: is SHUT_WR (%d) == 1?\n", SHUT_WR));

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_isfcantsendmore: before changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
	if (!(pcb->slirp_state & SS_NOFDREF)) {
		shutdown(slirp_fd, SHUT_WR);  /* SHUT_WR : further transmissions will be disallowed. */
		netif_slirp_events(pcb) &= ~(POLLIN | POLLPRI);
	}
	pcb->slirp_state &= ~(SS_ISFCONNECTING);

	if (pcb->slirp_state & SS_FCANTRCVMORE)
		pcb->slirp_state = SS_NOFDREF; /* as above */
	else
		pcb->slirp_state |= SS_FCANTSENDMORE;

	LWIP_DEBUGF(LWSLIRP_DEBUG, (" after changes: "));
	slirp_debug_print_state(LWSLIRP_DEBUG, pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));
}


/*
 * Set fd non-blocking
 */
static void slirp_fd_nonblock(int fd) {
	int opt;

	opt = fcntl(fd, F_GETFL, 0);
	opt |= O_NONBLOCK;
	fcntl(fd, F_SETFL, opt);
}

static void slirp_tcp_io(struct netif *netif, int posfd, void *arg)
{
	struct tcp_pcb *pcb = arg;
	struct stack *stack = netif->stack;
	int revents = stack->netif_pfd[posfd].revents;

	if (pcb->slirp_state & SS_NOFDREF || pcb->slirp_posfd == -1) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: tcp_pcb(%p) (->slirp_state & SS_NOFDREF) OR (->slirp == -1). return\n", pcb));
		return;
	}
	if (revents & POLLPRI) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: socket(%d) has urgent data, I read them.\n", pcb->slirp_posfd));
		if (netif->flags & NETIF_FLAG_UP) {
			if (slirp_read(pcb, posfd)) {
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: socket(%d) sending urgent data to tcp_output.\n", pcb->slirp_posfd));
				tcp_output(pcb);
			}
		} else
			slirp_discard_input(pcb);
	}
	if (revents & POLLIN) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: socket(%d) has data, I read them.\n", pcb->slirp_posfd));
		if (netif->flags & NETIF_FLAG_UP) {
			if (slirp_read(pcb, posfd)) {
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: socket(%d) sending data to tcp_output.\n", pcb->slirp_posfd));
				tcp_output(pcb);
			}
		} else
			slirp_discard_input(pcb);
	}
	if (revents & POLLOUT) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_io: socket(%d) sending data\n", pcb->slirp_posfd));
		slirp_write(pcb, posfd, netif);
	}
}

static void slirp_listening_io(struct netif *netif, int posfd, void *arg)
{
	struct tcp_pcb_listen *pcb = arg;
	struct stack *stack = netif->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);
	int revents = stack->netif_pfd[posfd].revents;
	if (pcb->slirp_state & SS_NOFDREF || pcb->slirp_posfd == -1) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listening_io: tcp_pcb(%p) (->slirp_state & SS_NOFDREF) OR (->slirp == -1). return\n", pcb));
		return;
	}
	if (revents & POLLOUT) {
		struct pseudo_iphdr piphdr;
		struct ip_addr src4,dest4;
		struct ip_addr_list *addr;
		int ret;

		if(pcb->slirp_state & SS_ISFCONNECTING) {
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listening_io: socket(%d) is try to connect to the peer (SS_ISFCONNECTING state)."
						"Is connected?... ", pcb->slirp_posfd));
			/* If ret > 0, the socket is still connecting, so
			 * the write is used to test this. */
			pcb->slirp_state &= ~SS_ISFCONNECTING;

			ret = write(slirp_fd, &ret, 0);
			if(ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK ||
						errno == EINPROGRESS || errno == ENOTCONN) {
					LWIP_DEBUGF(LWSLIRP_DEBUG, (" Not now, but is already trying.\n"));
					return;
				}

				/* else failed*/
				pcb->slirp_state = SS_NOFDREF;
				LWIP_DEBUGF(LWSLIRP_DEBUG, (" NO, so I set the state to SS_NOFDREF.\n"));
				return;
			}

			LWIP_DEBUGF(LWSLIRP_DEBUG, (" YES.\n"));
			/*
			 * Continue tcp_input
			 */
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listening_io: now that it is connected send the SYN to the stack and forawrd the pending packets\n"));

			/* I build a new pseudo header for tcp_input() */
			/* I don't test the return value of ip_build_piphdr because I know 
			 * that it's right, infact the packet in pbuf ->slirp_m was already controlled
			 * by ip_input() the first time it was arrived. */
			ip_build_piphdr(&piphdr, pcb->slirp_m, &src4, &dest4);

			/* I set the ip address list */
			addr = ip_addr_list_alloc(stack);
			if(addr == NULL) {
				/* There aren't no more ip_addr_list avaible, so I abort.*/
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listening_io: ip_addr_list_alloc() returned NULL, so I abort!\n"));
				abort();
			}

			addr->next = NULL;
			memcpy(&addr->ipaddr, &piphdr.dest, sizeof(struct ip_addr));

			tcp_input(pcb->slirp_m, addr, &piphdr, netif);

			/* free the ip address list*/
			ip_addr_list_free(stack, addr);
		}
	}
	if (revents & POLLIN) {
		/* nothing? */
	}
}

/* 
 * Connect to a host on the Internet
 * Called by tcp_input
 * Only do a connect, the tcp fields will be set in tcp_input
 * return 0 if there's a result of the connect,
 * else return -1 means we're still connecting
 * The return value is almost always -1 since the socket is
 * nonblocking.  Connect returns after the SYN is sent, and does 
 * not wait for ACK+SYN.
 */

int slirp_tcp_fconnect(struct tcp_pcb_listen *lpcb, u16_t dest_port, struct ip_addr *dest_addr,
		struct netif *slirpif)
{
	int ret = 0;
	int lslirp_fd;
	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_fconnect: start. Try to connect a socket to the listening tcp pcb.\n"));

	if((slirpif->flags & NETIF_FLAG_UP) 
			&& (lslirp_fd = slirpif->netifctl(slirpif, NETIFCTL_SLIRPSOCK_STREAM,NULL)) >= 0) {
		int opt;
		unsigned char version;
		struct sockaddr_in6 addr6;
		struct ip_addr *remote_addr;

		/* Set the socket non blocking */
		slirp_fd_nonblock(lslirp_fd);
		/* Set the socket options: reuse address ad in-line out of band data*/
		opt = 1;
		setsockopt(lslirp_fd,SOL_SOCKET,SO_REUSEADDR,(char *)&opt,sizeof(opt ));
		opt = 1;
		setsockopt(lslirp_fd,SOL_SOCKET,SO_OOBINLINE,(char *)&opt,sizeof(opt ));

		addr6.sin6_family = AF_INET6;

		version = ip_addr_is_v4comp(&lpcb->local_ip) ? 4 : 6;

		remote_addr = slirp_get_destaddr((struct udp_pcb *)lpcb, version);

		/* I convert remote_addr (a ip_addr IPv6 address) in a in6_addr. */
		SO_IP_ADDR2IN6_ADDR(remote_addr, &addr6.sin6_addr);

		addr6.sin6_port = htons(dest_port);
#if LWSLIRP_DEBUG
		{
			char str_addr6[INET6_ADDRSTRLEN];
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("tcp_fconnect: connect()ing, addr.sin_port = %d, "
						"addr.sin_addr.s_addr = %s\n", ntohs(addr6.sin6_port),
						inet_ntop(AF_INET6, &addr6.sin6_addr, str_addr6, sizeof(str_addr6))));
		}
#endif /* LWSLIRP_DEBUG */
		lpcb->slirp_posfd = netif_addfd(slirpif, lslirp_fd, slirp_listening_io, lpcb, 0);

		/* I do the connect*/
		ret = connect(lslirp_fd,(struct sockaddr *)&addr6, sizeof(addr6));
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("tcp_fconnect: after connect of socket %d, "
					"ret = %d\n", lpcb->slirp_posfd, ret));


		/*
		 * If it's not in progress, it failed, so we just return 0,
		 * without clearing SS_NOFDREF
		 */

		slirp_isfconnecting((struct tcp_pcb*) lpcb);
	}

	return ret;
}

void slirp_tcp_update_listen2data(struct tcp_pcb *pcb)
{
	LWIP_DEBUGF(TCP_INPUT_DEBUG, ("slirp_tcp_update_listen2data connection ok -> now data.\n"));
	netif_updatefd(pcb->stack, pcb->slirp_posfd, slirp_tcp_io, pcb, 0);
	netif_slirp_events(pcb) |= POLLPRI;
}

void slirp_tcp_close(struct tcp_pcb *pcb)
{
	int slirp_fd = netif_slirp_fd(pcb->stack,pcb);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_tcp_close connection closed.\n"));
	if (slirp_fd >= 0)
		close(slirp_fd);
	netif_delfd(pcb->stack,pcb->slirp_posfd);
}

/* UDP ****************************************************************************************/

/* from lwipv6 to slirp (outgoing stream). */

static int slirp_sendto(struct udp_pcb *pcb, struct pbuf *p, struct netif *slirpif);
static void slirp_udp_input(struct netif *netif, int posfd, void *arg);

int slirp_udp_bind(struct udp_pcb *pcb, struct netif *slirpif, int flags)
{
	int slirp_fd;
	if (slirpif->netifctl != NULL) {
		struct sockaddr_in6 addr6;
		LWIP_DEBUGF(UDP_DEBUG, ("slirp_udp_bind: I'll bind the socket to a %s address\n",
					ip_addr_is_v4comp(&pcb->local_ip) == 6 ? "IPv6" : "v4-mapped-v6"));

		if((slirp_fd = slirpif->netifctl(slirpif, NETIFCTL_SLIRPSOCK_DGRAM, NULL)) != -1) {
			memset(&addr6, 0, sizeof(&addr6));

			addr6.sin6_family = AF_INET6;
			addr6.sin6_port = 0;
			addr6.sin6_addr = in6addr_any;
			if( bind(slirp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
				/* Error, I close the socket */
				LWIP_DEBUGF(UDP_DEBUG, ("slirp_udp_bind: socket bind error.\n"));
				close(slirp_fd);
				pcb->slirp_posfd = -1;
			} else {
				/* success */
				LWIP_DEBUGF(UDP_DEBUG, ("slirp_udp_bind: socket bind successful\n"));
				pcb->slirp_expire = time_now() + UDP_PCB_EXPIRE;
				LWIP_DEBUGF(UDP_DEBUG, ("slirp_udp_bind: pcb->slirp_expire = (%ld + %ld) = %ld\n", time_now(),
							UDP_PCB_EXPIRE, pcb->slirp_expire));
				pcb->slirp_posfd = netif_addfd(slirpif, slirp_fd, slirp_udp_input, pcb, NETIF_ARGS_1SEC_POLL);
			}
		}
	}
}

void slirp_udp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
		struct ip_addr *addr, u16_t port) {
	LWIP_DEBUGF(UDP_DEBUG, ("slirp_udp_rcv: received pbuf %p, tot_len = %d\n", p, p->tot_len));
	
	{
		char str_addr[INET6_ADDRSTRLEN];
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_recv: FROM %s : %u\n",
					inet_ntop(AF_INET6, addr, str_addr, sizeof(str_addr)),
					port));
	}

	/* Try to send it */
	if(slirp_sendto(pcb, p, arg) == -1 ) {
		LWIP_DEBUGF(UDP_DEBUG, ("udp_input: slirp_sendto() error, I send a ICMP destination unreachable.\n"));
		/* icmp_dest_unreach() supports only IPv6, so I send it only
		 * if the connection is IPv6 */
		if(!ip_addr_is_v4comp(addr)) {
			pbuf_header(p, UDP_HLEN + IP_HLEN);
			icmp_dest_unreach(pcb->stack, p, ICMP_DUR_NET);
		}
	}

	/* It was send without errors, so I delete it. */
	pbuf_free(p);
}

static int slirp_sendto(struct udp_pcb *pcb, struct pbuf *p, struct netif *slirpif) {
	int ret;
	unsigned char version;
	char *full_payload, *temp;
	struct pbuf *q;
	struct sockaddr_in6 addr6;
	struct ip_addr *remote_addr;
	struct stack *stack = slirpif->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);

	if (!(slirpif->flags & NETIF_FLAG_UP))
		return -1;

	version = ip_addr_is_v4comp(&pcb->local_ip) ? 4 : 6;

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_sendto: I'll send a %s packet.\n", version == 6 ? "IPv6" : "v4-mapped-v6"));

	/* I sets the family */
	addr6.sin6_family = AF_INET6;

	remote_addr = slirp_get_destaddr(pcb, version);

	/* I convert remote_addr (a ip_addr IPv6 address) in a in6_addr. */
	SO_IP_ADDR2IN6_ADDR(remote_addr, &addr6.sin6_addr);

	addr6.sin6_port = htons(pcb->local_port);

#if LWSLIRP_DEBUG
	{
		char str_addr6[INET6_ADDRSTRLEN];
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_sendto: I send to %s : %u, using socket %d\n",
					inet_ntop(AF_INET6, &addr6.sin6_addr, str_addr6, sizeof(str_addr6)),
					ntohs(addr6.sin6_port), pcb->slirp_posfd));
	}
#endif /* LWSLIRP_DEBUG */

	/* put all the pbuff fragment in one buffer */
	full_payload = mem_malloc(p->tot_len);
	temp = full_payload;
	for(q = p; q != NULL; q = q->next) {
		memcpy(temp, q->payload, q->len);
		temp += q->len;
	}
	ret = sendto(slirp_fd, full_payload, p->tot_len, 0, (struct sockaddr *)&addr6, sizeof (addr6));
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_sendto: I have to send %d bytes, and I have send %d bytes\n",
				p->tot_len, ret));
	mem_free(full_payload);
	if( ret < 0 )
		return -1;
	/* Kill the socket if there's no reply in 4 minutes,
	 * but only if it's an expirable socket
	 */
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_sendto: BEFORE pcb->slirp_expire = %d -- ", pcb->slirp_expire));
	pcb->slirp_expire = time_now() + UDP_PCB_EXPIRE;
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("AFTER pcb->slirp_expire = (%ld + %ld) = %ld\n",
				time_now(), UDP_PCB_EXPIRE, pcb->slirp_expire));

	return 0;
}

static void slirp_udp_input(struct netif *netif, int posfd, void *arg)
{
	struct sockaddr_in6 addr6;
	int addrlen = sizeof(struct sockaddr_in6);
	struct pbuf *m;
	int n;
	int ret;
	struct udp_pcb *pcb = arg;
	struct stack *stack = netif->stack;
	int slirp_fd=netif_slirp_fd(stack, pcb);

	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_input: pcb = %p\n", pcb));

	/* get the number of bytes I can read from the read buffer */
	ret=ioctl(slirp_fd, FIONREAD, &n);
	//printf("0 %d n=%d ret=%d\n",slirp_fd,n,ret);

	if (n == 0) {
		unsigned long now=time_now();
		if (now > pcb->slirp_expire) {
			netif_delfd(stack,posfd);
			close(slirp_fd);
			udp_remove(pcb);
		}
		return;
	}

	/* create the buffer */
	m = pbuf_alloc(PBUF_TRANSPORT, n, PBUF_RAM);

	/* read the data*/
	ret = recvfrom(slirp_fd, m->payload, n, 0,(struct sockaddr *)&addr6, &addrlen);
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_input: called ioctl, I can read %d bytes, "
				"and I have read %d bytes, errno = %d-%s\n", n, ret, errno, strerror(errno)));

	if(ret == -1 || ret == 0) {
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_input: error.\n"));
		/* icmp_dest_unreach() supports only IPv6, so I send it only
		 * if the connection is IPv6 */
		if(!ip_addr_is_v4comp(&pcb->local_ip)) {
			enum icmp_dur_type type;
			struct pbuf *p;
			struct ip_hdr *iphdr;

			type = ICMP_DUR_PORT;
			if(errno == EHOSTUNREACH) type = ICMP_DUR_HOST;
			else if(errno == ENETUNREACH) type = ICMP_DUR_NET;

			/* Because icmp_dest_unreach() needs a pbuf, but I have not it,
			 * I create a pbuf  and I fill it with the necessary
			 * informations. */
			p = pbuf_alloc(PBUF_IP, IP_HLEN, PBUF_RAM);
			iphdr = p->payload;
			ip_addr_set(&iphdr->src, &pcb->remote_ip);
			ip_addr_set(&iphdr->dest, &pcb->local_ip);

			/* I send dest unreach */
			icmp_dest_unreach(stack, p, type);
			/* I free the packet created. */
			pbuf_free(p);
			pbuf_free(m);
		}
	} else {
		if (netif->flags & NETIF_FLAG_UP) {
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_input: src = "));
			ip_addr_debug_print(LWSLIRP_DEBUG, &pcb->local_ip);
			LWIP_DEBUGF(LWSLIRP_DEBUG, (", "));

			LWIP_DEBUGF(LWSLIRP_DEBUG, ("dest = "));
			ip_addr_debug_print(LWSLIRP_DEBUG, &pcb->remote_ip);
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("\n"));

			/* Hack: domain name lookup will be used the most for UDP,
			 * and since they'll only be used once there's no need
			 * for the 4 minute (or whatever) timeout... So we time them
			 * out much quicker (10 seconds  for now...)
			 */
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_udp_input: pcb->local_port = %d. BEFORE pcb->slirp_expire = %d --- "
						"AFTER pcb->slirp_expire = (%ld + ", pcb->local_port, pcb->slirp_expire, time_now()));
			if (pcb->local_port == 53) {
				pcb->slirp_expire = time_now() + UDP_PCB_EXPIREFAST;
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("%d", UDP_PCB_EXPIREFAST));
			} else {
				pcb->slirp_expire = time_now() + UDP_PCB_EXPIRE;
				LWIP_DEBUGF(LWSLIRP_DEBUG, ("%d", UDP_PCB_EXPIRE));
			}
			LWIP_DEBUGF(LWSLIRP_DEBUG, (") = %ld\n", pcb->slirp_expire));
			/* I send the data read */
			udp_sendto(pcb, m, &pcb->remote_ip, pcb->remote_port);
		}
		pbuf_free(m);
	}
}

/*============ listening ===================*/
struct slirp_listen {
	struct netif *slirpif;
	struct ip_addr destaddr;
	u16_t destport;
	u16_t srcport;
	union {
		struct ip_addr srcaddr;
		char srcpath[1];
	} src;
};

#define SLIRP_LISTEN_LEN(TYPE, SRC) \
	(((TYPE) == SLIRP_LISTEN_UNIXSTREAM) ? \
		sizeof(struct slirp_listen) - sizeof(struct ip_addr) + strlen(src) + 1 : \
		sizeof(struct slirp_listen))

int slirp_listen_delpos(struct stack *stack, int pos)
{
	close(stack->netif_pfd[pos].fd);
	if (stack->netif_pfd_args[pos].funarg != NULL)
		mem_free(stack->netif_pfd_args[pos].funarg);
}

/* the stack received a connection request 
	 (or the first datagram from a new source) */ 
static void slirp_listen_cb(struct netif *netif, int pos, void *arg)
{
	struct slirp_listen *sl = arg;
	struct stack *stack=netif->stack;
	int ret;
	int slirp_fd=stack->netif_pfd[pos].fd;
	
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_cb: new data on %d\n", slirp_fd));

	if (stack->netif_pfd_args[pos].flags & SLIRP_LISTEN_UDP) {
		/*DGRAM*/
		int n;
		struct pbuf *m;
		struct sockaddr_in6 srcaddr;
		struct udp_pcb *udp_pcb=NULL;
		int srclen = sizeof(struct sockaddr_in6);
		int lwsrcport;
		ioctl(slirp_fd, FIONREAD, &n);
		m = pbuf_alloc(PBUF_TRANSPORT, n, PBUF_RAM);
		if (m==NULL)
			return;
		ret = recvfrom(slirp_fd, m->payload, n, 0,(struct sockaddr *)&srcaddr, &srclen);
		if(ret == -1 || ret == 0) 
			goto udp_err;
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_cb: udp packet on %d\n", slirp_fd));
		/* create a new unconnected socket for new udp sequence 
			 from a different source/port */
		if (!stack->netif_pfd_args[pos].flags & SLIRP_LISTEN_ONCE)
			lwip_slirp_listen_add(sl->slirpif, &sl->destaddr, sl->destport, &sl->src.srcaddr, sl->srcport, 
					stack->netif_pfd_args[pos].flags);
		/* connect the current socket to the source of the first packet */
		ret = connect(slirp_fd,(struct sockaddr *)&srcaddr,srclen);
		lwsrcport=ntohs(srcaddr.sin6_port);
		if ((udp_pcb = udp_new(stack)) == NULL) 
			goto udp_err;
		/* set up the new udp pcb */
		udp_recv(udp_pcb, slirp_udp_recv, sl->slirpif);
		udp_pcb->so_options |=  SOF_REUSEPORT;
		/* bind the pcb to the source of the packet (such that the packet
		will be forwarded with the right/real-world src/srcport) */
		ret = udp_bind(udp_pcb, (struct ip_addr *)&(srcaddr.sin6_addr), ntohs(srcaddr.sin6_port), NULL);
		udp_pcb->slirp_expire = time_now() + UDP_PCB_EXPIRE;
		/* add the socket to the main event loop poll (with the new parms) */
		udp_pcb->slirp_posfd = netif_addfd(sl->slirpif, slirp_fd, slirp_udp_input, udp_pcb, NETIF_ARGS_1SEC_POLL);
		/* connect the socket to the (virtual LWIP-side) remote address
			 (target of forwarding) */
		ret=udp_connect(udp_pcb, &sl->destaddr, sl->destport);
		/* remove the old listening item from the main loop */
		netif_delfd(stack, pos);
		mem_free(arg);
		/* forward the first packet */
		udp_sendto(udp_pcb, m, &udp_pcb->remote_ip, udp_pcb->remote_port);
udp_err:
		pbuf_free(m);
		return;
	} else {
		/*STREAM*/
		int conn;
		struct sockaddr_in6 srcaddr;
		int srclen = sizeof(srcaddr);
		struct tcp_pcb *pcb;
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_cb: tcp/unixsream packet on %d\n", slirp_fd));
		memset(&srcaddr,0,srclen);
		/* accept: unfortunately we have to accept the connection request
			 to read the address/port of the client end */
		conn=accept(slirp_fd, (struct sockaddr *)&srcaddr, &srclen);
		if (conn < 0)
			goto tcp_err;
#if LWSLIRP_DEBUG
		{
			char str_addr6[INET6_ADDRSTRLEN];
			LWIP_DEBUGF(LWSLIRP_DEBUG, ("ACCEPT: connect()ing, addr.sin_port = %d, "
						"addr.sin_addr.s_addr = %s\n", ntohs(srcaddr.sin6_port),
						inet_ntop(AF_INET6, &srcaddr.sin6_addr, str_addr6, sizeof(str_addr6))));
		}
#endif
		/* new pcb tcp */
		if ((pcb = tcp_new(stack)) == NULL)
			goto tcp_err;
		struct ip_addr *ipaddr=(struct ip_addr *)&(srcaddr.sin6_addr);
		/* set up the new tcp connection... */
		tcp_arg(pcb, NULL);
		/* callbacks */
		tcp_recv(pcb, slirp_tcp_recv);
		/* bind to "fake" the remote sender on the packets */
		tcp_bind(pcb, (struct ip_addr *)&(srcaddr.sin6_addr), ntohs(srcaddr.sin6_port));
		/* add the new fd to the main eventi loop */
		pcb->slirp_posfd = netif_addfd(sl->slirpif, conn, slirp_listening_io, pcb, 0);
		/* connect to the internal/virtual/lwipv6 end of the connection */
		tcp_connect(pcb, &sl->destaddr, sl->destport, slirp_tcp_connected);
		if (stack->netif_pfd_args[pos].flags & SLIRP_LISTEN_ONCE) {
			close(slirp_fd);
			/* remove the old listening item from the main loop */
			netif_delfd(stack, pos);
			mem_free(arg);
		}

		return;
tcp_err:
		close(conn);
		return;
	}
}

/* add a port forwarding rule.
	 src/srcport is the local address/port (in the native stack)
	 dest/destport is the virtual address/port where all the 
	 traffic to src/srcport must be forwarded */
int lwip_slirp_listen_add(struct netif *slirpif,
		struct ip_addr *dest,  int destport,
		void *src,  int srcport, int flags)
{
	int s;
	int conntype=flags & SLIRP_LISTEN_TYPEMASK;
	struct slirp_listen *sl_item;
	struct stack *stack=slirpif->stack;;
	int ret;
	int one=1;
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: srcport %d flags %x\n",
				srcport, flags));
	if (conntype == SLIRP_LISTEN_UNIXSTREAM && src==NULL)
		return ERR_VAL;
	sl_item=mem_malloc(SLIRP_LISTEN_LEN(conntype, src));
	if (sl_item==NULL)
		return ERR_MEM;
	ip_addr_set(&sl_item->destaddr,dest);
	sl_item->destport=destport;
	sl_item->srcport=srcport;
	sl_item->slirpif=slirpif;
	/* TCP-IP port forwarding */
	if (conntype == SLIRP_LISTEN_TCP || conntype == SLIRP_LISTEN_UDP) {
		struct sockaddr_in6 srcsockaddr;
		memset(&srcsockaddr,0,sizeof(srcsockaddr));
		ip_addr_set(&sl_item->src.srcaddr,src);
		/* create the socket */
		s=slirpif->netifctl(slirpif, 
				(conntype == SLIRP_LISTEN_UDP)?NETIFCTL_SLIRPSOCK_DGRAM:NETIFCTL_SLIRPSOCK_STREAM, NULL);
		if (s < 0) {
			ret=ERR_CONN;
			goto err_free;
		}
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: new tcp/udp socket %d\n", s));
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		srcsockaddr.sin6_family=AF_INET6;
		srcsockaddr.sin6_port=htons(srcport);
		memcpy(&srcsockaddr.sin6_addr,src,sizeof(struct ip_addr));
		/* bind it to the right address/port */
		if(bind(s, (struct sockaddr *) &srcsockaddr, sizeof(srcsockaddr)) < 0) {
			ret=ERR_CONN;
			goto err_close;
		}
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: socket %d bound to the local address/port %d\n", s, srcport));
	} else if (conntype == SLIRP_LISTEN_UNIXSTREAM) {
		struct sockaddr_un srcsockaddr;
		/* Unix stream create */
		memset(&srcsockaddr,0,sizeof(srcsockaddr));
		if (strlen(src) + 1 > sizeof(srcsockaddr.sun_path)) {
			ret=ERR_VAL;
			goto err_free;
		}
		sl_item->srcport=srcport;
		strcpy(sl_item->src.srcpath,src);
		s=socket(AF_UNIX, SOCK_STREAM, 0);
		if (s < 0) {
			ret=ERR_CONN;
			goto err_free;
		}
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: new unix socket %d\n", s));
		srcsockaddr.sun_family=AF_UNIX;
		strcpy(srcsockaddr.sun_path,src);
		/* Unix stream bind */
		if(bind(s, (struct sockaddr *) &srcsockaddr, sizeof(srcsockaddr)) < 0) {
			ret=ERR_CONN;
			goto err_close;
		}
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: unix socket %d bound to the local address/port %d\n", s, srcport));
	} else {
		ret=ERR_ARG;
		goto err_free;
	}
	//setsockopt(3, SOL_SOCKET, SO_OOBINLINE, [1], 4);
	/* connection oriented forwarding services need listen */
  if ((conntype == SLIRP_LISTEN_TCP || conntype == SLIRP_LISTEN_UNIXSTREAM)) {
		if (listen(s,5) < 0) {
			ret=ERR_CONN;
			goto err_close;
		}
		LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: stream socket %d listen ok\n", s));
	}
	/* add the fd descriptor */
	if (netif_addfd(slirpif, s, slirp_listen_cb, sl_item, flags) < 0) {
		ret=ERR_CONN;
		goto err_close;
	}
	LWIP_DEBUGF(LWSLIRP_DEBUG, ("slirp_listen_add: stream socket %d listen ok\n", s));
	return ERR_OK;
err_close:
	close(s);
err_free:
	mem_free(sl_item);
	return ERR_CONN;
}

int lwip_slirp_listen_del(struct netif *slirpif,
		struct ip_addr *dest,  int destport,
		void *src,  int srcport, int flags)
{
	struct stack *stack=slirpif->stack;
	int n;
	int ret;
	for (n=0; n<stack->netif_npfd && stack->netif_pfd[n].fd >= 0; n++) {
		struct slirp_listen *sl=stack->netif_pfd_args[n].funarg;
		int conntype=stack->netif_pfd_args[n].flags & SLIRP_LISTEN_TYPEMASK;
		if ((flags & SLIRP_LISTEN_TYPEMASK) == (conntype & SLIRP_LISTEN_TYPEMASK) &&
				(ip_addr_cmp(dest,&sl->destaddr)==0) &&
				destport == sl->destport && srcport == sl->srcport &&
				(conntype == SLIRP_LISTEN_UNIXSTREAM) ? (strcmp(src,sl->src.srcpath)==0) : 
				(memcmp(src,&sl->src.srcaddr,sizeof(struct ip_addr))==0))
			return slirp_listen_delpos(stack,n);
	}
	return ERR_VAL;
}


#if LWSLIRP_DEBUG
void slirp_debug_print_state(int debk, struct tcp_pcb *pcb) {
	int i = 0;
	LWIP_DEBUGF(debk, ("Socket States: "));
	if ((pcb->slirp_state & SS_NOFDREF) == SS_NOFDREF)
		LWIP_DEBUGF(debk, ("%sSS_NOFDREF", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_ISFCONNECTING) == SS_ISFCONNECTING)
		LWIP_DEBUGF(debk, ("SS_ISFCONNECTING%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_ISFCONNECTED) == SS_ISFCONNECTED)
		LWIP_DEBUGF(debk, ("SS_ISFCONNECTED%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_FCANTRCVMORE) == SS_FCANTRCVMORE)
		LWIP_DEBUGF(debk, ("SS_FCANTRCVMORE%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_FCANTSENDMORE) == SS_FCANTSENDMORE)
		LWIP_DEBUGF(debk, ("SS_FCANTSENDMORE%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_FWDRAIN) == SS_FWDRAIN)
		LWIP_DEBUGF(debk, ("SS_FWDRAIN%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_CTL) == SS_CTL)
		LWIP_DEBUGF(debk, ("SS_CTL%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_FACCEPTCONN) == SS_FACCEPTCONN)
		LWIP_DEBUGF(debk, ("SS_FACCEPTCONN%s", i++ > 0 ? ", " : ""));
	if ((pcb->slirp_state & SS_FACCEPTONCE) == SS_FACCEPTONCE)
		LWIP_DEBUGF(debk, ("SS_FACCEPTONCE%s", i++ > 0 ? ", " : ""));

	if(i == 0)
		LWIP_DEBUGF(debk, ("NO FLAG SET"));
}
#endif /* LWSLIRP_DEBUG */


#endif
