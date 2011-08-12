/*
 * Slirpvde6 BOOTP/DHCP server
 * Copyright (c) 2010 Renzo Davoli
 * Based on QEMU BOOTP/DHCP server
 * Copyright (c) 2004 Fabrice Bellard
 *
 * This file is part of SlirpVde6.
 *
 * SlirpVde6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SlirpVde6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SlirpVde6.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "bootp.h"
#include <lwipv6.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include "slirpvde6.h"

/* XXX: only DHCP is supported */

#define LEASE_TIME (24 * 3600)

static const uint8_t rfc1533_cookie[] = { RFC1533_COOKIE };

#ifdef DEBUG
#define dprintf(fmt, ...) \
do { fprintf(stderr, fmt, ##  __VA_ARGS__); fflush(stderr); } while (0)
#else
#define dprintf(fmt, ...)
#endif

extern void lwip_inet_mask(int bits, struct ip_addr *addr, struct ip_addr *mask);
extern struct ip_addr *dhcphost;
extern int dhcpmask;
extern struct ip_addr *dhcpnameserver;
extern struct ip_addr vdhcp_start;
extern int vdhcp_naddr;

char *bootp_filename=NULL;
char *client_hostname=NULL;
int restricted=0;

static BOOTPClient *bootp_clients;

static BOOTPClient *get_new_addr(struct in_addr *paddr,
                                 const uint8_t *macaddr)
{
    BOOTPClient *bc;
    int i;

    for(i = 0; i < NB_BOOTP_CLIENTS; i++) {
        bc = &bootp_clients[i];
        if (!bc->allocated || !memcmp(macaddr, bc->macaddr, 6))
            goto found;
    }
    return NULL;
 found:
    bc = &bootp_clients[i];
    bc->allocated = 1;
    paddr->s_addr = vdhcp_start.addr[3] + htonl(i);
    return bc;
}

static BOOTPClient *request_addr(const struct in_addr *paddr,
                                 const uint8_t *macaddr)
{
    uint32_t req_addr = ntohl(paddr->s_addr);
    uint32_t dhcp_addr = ntohl(vdhcp_start.addr[3]);
    BOOTPClient *bc;

    if (req_addr >= dhcp_addr &&
        req_addr < (dhcp_addr + NB_BOOTP_CLIENTS)) {
        bc = &bootp_clients[req_addr - dhcp_addr];
        if (!bc->allocated || !memcmp(macaddr, bc->macaddr, 6)) {
            bc->allocated = 1;
            return bc;
        }
    }
    return NULL;
}

static BOOTPClient *find_addr(struct in_addr *paddr,
                              const uint8_t *macaddr)
{
    BOOTPClient *bc;
    int i;

    for(i = 0; i < NB_BOOTP_CLIENTS; i++) {
        if (!memcmp(macaddr, bootp_clients[i].macaddr, 6))
            goto found;
    }
    return NULL;
 found:
    bc = &bootp_clients[i];
    bc->allocated = 1;
    paddr->s_addr = vdhcp_start.addr[3] + htonl(i);
    return bc;
}

static int dhcp_decode(const struct bootp_t *bp, int *pmsg_type,
                        const struct in_addr **preq_addr, 
												char *client_ethaddr)
{
    const uint8_t *p, *p_end;
    int len, tag;

    *pmsg_type = 0;
    *preq_addr = NULL;

		if (bp->bp_htype != 1 && bp->bp_hlen != 6)
			return -1;
    p = bp->bp_vend;
    p_end = p + DHCP_OPT_LEN;
    if (memcmp(p, rfc1533_cookie, 4) != 0)
        return -1;
    p += 4;
    while (p < p_end) {
        tag = p[0];
        if (tag == RFC1533_PAD) {
            p++;
        } else if (tag == RFC1533_END) {
            break;
        } else {
            p++;
            if (p >= p_end)
                break;
            len = *p++;
            dprintf("dhcp: tag=%d len=%d\n", tag, len);

            switch(tag) {
            case RFC2132_MSG_TYPE:
                if (len >= 1)
                    *pmsg_type = p[0];
                break;
            case RFC2132_REQ_ADDR:
                if (len >= 4)
                    *preq_addr = (struct in_addr *)p;
                break;
            default:
                break;
            }
            p += len;
        }
    }
    if (*pmsg_type == DHCPREQUEST && !*preq_addr && bp->bp_ciaddr.s_addr) {
        *preq_addr = &bp->bp_ciaddr;
    }
		memcpy(client_ethaddr,bp->bp_hwaddr,bp->bp_hlen);
		return 0;
}

static void bootp_reply(int fd, const struct bootp_t *bp)
{
    BOOTPClient *bc = NULL;
    struct bootp_t reply;
    struct bootp_t *rbp=&reply;
    struct sockaddr_in saddr, daddr;
    struct in_addr vnetwork_mask;
    const struct in_addr *preq_addr;
    int dhcp_msg_type, val;
    uint8_t *q;
		char client_ethaddr[6];
		memset(rbp, 0, sizeof(struct bootp_t));

		saddr.sin_family=AF_INET;
		daddr.sin_family=AF_INET;
    /* extract exact DHCP msg type */
    if (dhcp_decode(bp, &dhcp_msg_type, &preq_addr, client_ethaddr) < 0) {
			dprintf("bootp ERROR packet op=%d msgtype=%d", bp->bp_op, dhcp_msg_type);
			return;
		}
    dprintf("bootp packet op=%d msgtype=%d", bp->bp_op, dhcp_msg_type);
    if (preq_addr)
        dprintf(" req_addr=%08x\n", ntohl(preq_addr->s_addr));
    else
        dprintf("\n");

    if (dhcp_msg_type == 0)
        dhcp_msg_type = DHCPREQUEST; /* Force reply for old BOOTP clients */

    if (dhcp_msg_type != DHCPDISCOVER &&
        dhcp_msg_type != DHCPREQUEST)
        return;

    if (dhcp_msg_type == DHCPDISCOVER) {
        if (preq_addr) {
            bc = request_addr(preq_addr, client_ethaddr);
            if (bc) {
                daddr.sin_addr = *preq_addr;
            }
        }
        if (!bc) {
         new_addr:
            bc = get_new_addr(&daddr.sin_addr, client_ethaddr);
            if (!bc) {
                dprintf("no address left\n");
                return;
            }
        }
        memcpy(bc->macaddr, client_ethaddr, 6);
    } else if (preq_addr) {
        bc = request_addr(preq_addr, client_ethaddr);
        if (bc) {
            daddr.sin_addr = *preq_addr;
            memcpy(bc->macaddr, client_ethaddr, 6);
        } else {
            daddr.sin_addr.s_addr = 0;
        }
    } else {
        bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
        if (!bc) {
            /* if never assigned, behaves as if it was already
               assigned (windows fix because it remembers its address) */
            goto new_addr;
        }
    }

    saddr.sin_addr.s_addr = dhcphost->addr[3];
		{
			struct ip_addr tmpmask;
			lwip_inet_mask(dhcpmask,dhcphost,&tmpmask);
			vnetwork_mask.s_addr=tmpmask.addr[3];
		}

    saddr.sin_port = htons(BOOTP_SERVER);

    daddr.sin_port = htons(BOOTP_CLIENT);

    rbp->bp_op = BOOTP_REPLY;
    rbp->bp_xid = bp->bp_xid;
    rbp->bp_htype = 1;
    rbp->bp_hlen = 6;
    memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, 6);

    rbp->bp_yiaddr = daddr.sin_addr; /* Client IP address */
    rbp->bp_siaddr = saddr.sin_addr; /* Server IP address */

    q = rbp->bp_vend;
    memcpy(q, rfc1533_cookie, 4);
    q += 4;

    if (bc) {
        dprintf("%s addr=%08x\n",
                (dhcp_msg_type == DHCPDISCOVER) ? "offered" : "ack'ed",
                ntohl(daddr.sin_addr.s_addr));

        if (dhcp_msg_type == DHCPDISCOVER) {
            *q++ = RFC2132_MSG_TYPE;
            *q++ = 1;
            *q++ = DHCPOFFER;
        } else /* DHCPREQUEST */ {
            *q++ = RFC2132_MSG_TYPE;
            *q++ = 1;
            *q++ = DHCPACK;
        }

        if (bootp_filename)
            snprintf((char *)rbp->bp_file, sizeof(rbp->bp_file), "%s",
                     bootp_filename);

        *q++ = RFC2132_SRV_ID;
        *q++ = 4;
        memcpy(q, &saddr.sin_addr, 4);
        q += 4;

        *q++ = RFC1533_NETMASK;
        *q++ = 4;
        memcpy(q, &vnetwork_mask, 4);
        q += 4;

        if (!restricted) {
            *q++ = RFC1533_GATEWAY;
            *q++ = 4;
            memcpy(q, &saddr.sin_addr, 4);
            q += 4;

            *q++ = RFC1533_DNS;
            *q++ = 4;
						if (dhcpnameserver != NULL)
							memcpy(q, &dhcpnameserver->addr[3], 4);
						else {
							struct ip_addr tmpnameserver;
							get_dns_addr(&tmpnameserver);
							/* I hope it is V4 */
							memcpy(q, &tmpnameserver.addr[3], 4);
						}
            q += 4;
        }

        *q++ = RFC2132_LEASE_TIME;
        *q++ = 4;
        val = htonl(LEASE_TIME);
        memcpy(q, &val, 4);
        q += 4;

        if (client_hostname && *client_hostname) {
            val = strlen(client_hostname);
            *q++ = RFC1533_HOSTNAME;
            *q++ = val;
            memcpy(q, client_hostname, val);
            q += val;
        }
    } else {
        static const char nak_msg[] = "requested address not available";

        dprintf("nak'ed addr=%08x\n", ntohl(preq_addr->s_addr));

        *q++ = RFC2132_MSG_TYPE;
        *q++ = 1;
        *q++ = DHCPNAK;

        *q++ = RFC2132_MESSAGE;
        *q++ = sizeof(nak_msg) - 1;
        memcpy(q, nak_msg, sizeof(nak_msg) - 1);
        q += sizeof(nak_msg) - 1;
    }
    *q++ = RFC1533_END;

		dprintf("Registering arp %08x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
				ntohl(daddr.sin_addr.s_addr),
				client_ethaddr[0], client_ethaddr[1], client_ethaddr[2],
				client_ethaddr[3], client_ethaddr[4], client_ethaddr[5]);
		struct arpreq ar;
		memset(&ar,0,sizeof(ar));
		strcpy(ar.arp_dev,"vd0");
		ar.arp_pa=*((struct sockaddr *)&daddr);
		ar.arp_ha.sa_family=AF_UNSPEC;
		memcpy(&ar.arp_ha.sa_data,client_ethaddr,6);
		lwip_ioctl(fd,SIOCSARP,&ar);

		lwip_sendto(fd, rbp, sizeof(struct bootp_t), 0, (struct sockaddr *)&daddr, sizeof(daddr));

}

static void bootp_input(int fd, void *arg)
{
    struct bootp_t bp;
		int len=lwip_read(fd, &bp, sizeof(bp));
    if (bp.bp_op == BOOTP_REQUEST) {
			bootp_reply(fd, &bp);
    }
}

void bootp_init(struct stack *stack, int dhcp_naddr)
{
	struct sockaddr_in saddr;
	int one=1;
	int dhcpfd;
	bootp_clients=calloc(dhcp_naddr,sizeof(BOOTPClient));
	dhcpfd = lwip_msocket(stack, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(67);
	saddr.sin_addr.s_addr = INADDR_ANY;
	lwip_bind(dhcpfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	lwip_setsockopt(dhcpfd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
	slirpoll_addfd(dhcpfd, bootp_input, NULL);
}
