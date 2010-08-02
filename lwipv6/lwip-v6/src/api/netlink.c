/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
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

#include <sys/types.h>
#include "lwip/opt.h"

#if LWIP_NL 

#include "lwip/api.h"
#include "lwip/sockets.h"
#include "lwip/netlink.h"

#include "lwip/netif.h"
#include "ipv6/lwip/ip_route.h"
#include "ipv6/lwip/ip_addr.h"

#define MAX_NL 4

#define BUF_STDLEN 8192

struct netlinkbuf {
	int length;
	char *data;
};

struct netlink {

	struct stack *stack;

	char flags;
	int proto;
	u32_t pid;
	struct sockaddr_nl name;
	struct nlmsghdr hdr;
	struct pbuf *answer[2];
	int sndbufsize;
	int rcvbufsize;
} nl_t[MAX_NL];

#define NL_ALLOC (0x1)
static u32_t pid_counter;

void netlink_addanswer(void *inbuf,int *offset,void *in,int len)
{
	char *s=in;
	struct netlinkbuf *buf=inbuf;
	register int i;
	for (i=0; i<len && *offset<buf->length; i++, (*offset)++)
		buf->data[(*offset)]=s[i];
}

int mask2prefix (struct ip_addr *netmask)
{
	int result=0;
	register int i,j;

	for (i=0; i<4; i++)
		if (~netmask->addr[i]==0)
			result+=32;
		else
			break;

	if (i<4 && netmask->addr[i] != 0) 
		for (j=0; j<32; j++)
			if (ntohl(netmask->addr[i]) & 1 << (31 - j))
				result++;

	return result;
}

void prefix2mask(int prefix,struct ip_addr *netmask)
{
	register int i,j;
	register int tmp;

	for (i=0; i<4; i++, prefix -= 32) {
		if (prefix > 32)
			netmask->addr[i]=0xffffffff;
		else if (prefix > 0) {
			tmp=0;
			for (j=0;j<prefix;j++)
				tmp |= (1 << (31 - j));
			netmask->addr[i]=htonl(tmp);
		} 
		else
			netmask->addr[i]=0;
	}
}
			
typedef void (*netlink_mgmt)(struct stack *stack, struct nlmsghdr *msg,void * buf,int *offset);

static netlink_mgmt mgmt_table[]={
	/* NEW/DEL/GET/SET link */
	netif_netlink_adddellink,
	netif_netlink_adddellink,
	netif_netlink_getlink,
	NULL,
	/* NEW/DEL/GET addr */
	netif_netlink_adddeladdr, 
	netif_netlink_adddeladdr, 
	netif_netlink_getaddr, 
	NULL,
	/* NEW/DEL/GET route */
	ip_route_netlink_adddelroute, 
	ip_route_netlink_adddelroute, 
	ip_route_netlink_getroute, 
	NULL
};
#define MGMT_TABLE_SIZE (sizeof(mgmt_table)/sizeof(netlink_mgmt))

void netlink_ackerror(void *msg,int ackerr,void *buf,int *offset)
{
	struct nlmsghdr *h=(struct nlmsghdr *)msg;
	int myoffset=*offset;
	int restorelen=h->nlmsg_len;
	/*printf("netlink_ackerror %d\n",ackerr);*/
	*offset += sizeof(struct nlmsghdr);
	netlink_addanswer(buf,offset,&ackerr,sizeof(int));
	netlink_addanswer(buf,offset,msg,sizeof(struct nlmsghdr));
	h->nlmsg_len=*offset-myoffset;
	h->nlmsg_flags=0;
	h->nlmsg_type=NLMSG_ERROR;
	netlink_addanswer(buf,&myoffset,msg,sizeof(struct nlmsghdr));
	h->nlmsg_len=restorelen;
}

static void netlink_decode (struct stack *stack, void *msg,int size,int bufsize,struct pbuf **out,u32_t pid)
{
	//char buf[BUF_MAXLEN];
	struct netlinkbuf nlbuf;
	struct nlmsghdr *h=(struct nlmsghdr *)msg;

	int offset=0;	
	if ((nlbuf.data=(char *) malloc (bufsize)) == NULL)
		nlbuf.length=0;
	else
		nlbuf.length=bufsize;
	/*int success=1;*/

	while (NLMSG_OK(h, size)) {
		/*int err;*/
		int type;

		/*printf("h->nlmsg_type %x %d\n",h->nlmsg_type,h->nlmsg_type);*/
		if (h->nlmsg_type == NLMSG_DONE)
			return;
		type=h->nlmsg_type - RTM_BASE;
		h->nlmsg_pid=pid;
		if (type >= 0 && type < MGMT_TABLE_SIZE && mgmt_table[type] != NULL)
			mgmt_table[type](stack, h,&nlbuf,&offset);

		h = NLMSG_NEXT(h, size);
	}
	if (size) {
		fprintf(stderr, "netlink malformed packet: extra %d bytes\n", size);
	}
	if (offset > 0) {
		*out=pbuf_alloc(PBUF_RAW,offset,PBUF_RAM);
		memcpy((*out)->payload,nlbuf.data,offset);
	}
	free(nlbuf.data);
}


#if 0
static void dump(char *data,int size)
{
	register int i,j;
	printf("DUMP size=%d\n",size);
	for (i=0; i<(size+15)/16; i++) {
		for (j=0; j<16; j++) 
			if (i*16+j < size)
				printf("%02x ",data[i*16+j]);
			else
				printf("   ");
		for (j=0; j<16; j++) 
			if (i*16+j < size)
				printf("%c ",(data[i*16+j]>=' ' &&
							data[i*16+j] <= '~')?
						data[i*16+j]:'.');
			else
				printf("   ");
		printf("\n");
	}
}
#endif

	struct netconn *
netlink_open(struct stack *stack, int type,int proto)
{
	register int i;
	for (i=0;i<MAX_NL && (nl_t[i].flags & NL_ALLOC);i++)
		;
	if (i == MAX_NL)
		return (NULL);
	else  {
		nl_t[i].stack  = stack;

		nl_t[i].flags |= NL_ALLOC;
		nl_t[i].proto=proto;
		nl_t[i].pid=++pid_counter;
		nl_t[i].answer[0]=NULL;
		nl_t[i].answer[1]=NULL;
		nl_t[i].sndbufsize=BUF_STDLEN;
		nl_t[i].rcvbufsize=BUF_STDLEN;
		return (struct netconn *)(&nl_t[i]);
	}
}

	int
netlink_accept(void *sock, struct sockaddr *addr, socklen_t *addrlen)
{
	/*printf("netlink_accept\n");*/
	return 0;
}

	int
netlink_bind(void *sock, struct sockaddr *name, socklen_t namelen)
{
	struct netlink *nl=sock;
	/*printf("netlink_bind\n");*/
	/* is it useful? */
	memcpy(&(nl->name),name,sizeof(struct sockaddr_nl));
	return 0;
}

	int
netlink_close(void *sock)
{
	struct netlink *nl=sock;
	/*printf("netlink_close\n");*/
	nl->flags &= ~NL_ALLOC;
	return 0;
}

	int
netlink_connect(void *sock, struct sockaddr *name, socklen_t namelen)
{
	/*printf("netlink_connect\n");*/
	return 0;
}

	int
netlink_recvfrom(void *sock, void *mem, int len, unsigned int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	struct netlink *nl=sock;

	struct stack *stack = nl->stack;	

	/*printf("netlink_recvfrom\n");*/
	if (from) {
		memset(from,0,*fromlen);
		from->sa_family=PF_NETLINK;
	}
	if (nl->answer[0]==NULL) {
		/*printf("netlink: answNULL\n");*/
		return 0;
	}
	/* it is not able to split the answer into several messages */
	else if (nl->answer[0]->tot_len > len) {
		pbuf_free(nl->answer[0]);
		nl->answer[0]=NULL;
		if (nl->answer[1] != NULL) {
			pbuf_free(nl->answer[1]);
			nl->answer[1]=NULL;
		}
		/*printf("LEN %d\n",len);*/
		return 0;
	} 
	else {
		register int outlen=nl->answer[0]->tot_len;
		memcpy(mem,nl->answer[0]->payload,outlen);
		/*printf("ANSWER\n"); dump(mem,outlen);*/
		pbuf_free(nl->answer[0]);
		nl->answer[0]=nl->answer[1];
		nl->answer[1]=NULL;
		return outlen;
	}
}

	int
netlink_send(void *sock, void *data, int size, unsigned int flags)
{
	struct netlink *nl=sock;

	struct stack *stack = nl->stack;

	/*printf("netlink_send\n"); dump(data,size);*/
	/* one single answer pending, multiple requests return one long answer */
	/*if (0 && nl->answer[0] != NULL)
		return (-1);
		else { */
	netlink_decode(stack, data,size,nl->rcvbufsize,nl->answer,nl->pid);
	memcpy(&(nl->hdr),data,sizeof(struct nlmsghdr));
	return 0;
	/*}*/
}

	int
netlink_sendto(void *sock, void *data, int size, unsigned int flags,
		struct sockaddr *to, socklen_t tolen)
{
	/*printf("netlink_sendto\n");*/
	netlink_send(sock,data,size,flags);
	return 0;
}

	int
netlink_getsockname (void *sock, struct sockaddr *name, socklen_t *namelen)
{
	struct netlink *nl=sock;
	struct sockaddr_nl snl;
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = PF_NETLINK;
	snl.nl_pid=nl->pid;
	snl.nl_groups=0;
	/*printf("netlink_getsockname\n");*/
	memcpy(name,&snl,sizeof(snl));
	*namelen=sizeof(snl);
	return(0);
}

	int 
netlink_getsockopt (void *sock, int level, int optname, void *optval, socklen_t *optlen)
{
	struct netlink *nl=sock;
	int err=0;
	//printf("netlink_getsockopt\n");
	switch( level ) {
		case SOL_SOCKET:
			switch(optname) {
				case SO_RCVBUF:
				case SO_SNDBUF:
					if( *optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				default:
					err = ENOPROTOOPT;
			}
			break;
		default:
			err = ENOPROTOOPT;
	}  /* switch */

	if( err != 0 ) {
		return err;
	} else
	{

		switch( level ) {
			case SOL_SOCKET:
				switch(optname) {
					case SO_RCVBUF:
						nl->rcvbufsize= *(int *) optval;
						break;
					case SO_SNDBUF:
						//printf("SO_SNDBUF\n");
						nl->sndbufsize= *(int *) optval;
						break;
				}
				break;
		}  /* switch */
		return 0;
	}
}

	int 
netlink_setsockopt (void *sock, int level, int optname, const void *optval, socklen_t optlen)
{
	struct netlink *nl=sock;
	int err=0;
	//printf("netlink_setsockopt %d\n",optname);
	switch( level ) {
		case SOL_SOCKET:
			switch(optname) {
				case SO_RCVBUF:
				case SO_SNDBUF:
					if( optlen < sizeof(int) ) {
						//printf("EINVAL\n");
						err = EINVAL;
					}
					break;
				default:
					//printf("ENOPROTOOPT1\n");
					err = ENOPROTOOPT;
			}
			break;
		default:
			//printf("ENOPROTOOPT2\n");
			err = ENOPROTOOPT;
	}  /* switch */

	if(err != 0 ) {
		return err;
	} 
	else {

		switch( level ) {
			case SOL_SOCKET:
				switch(optname) {
					case SO_RCVBUF:
						*(int *) optval =nl->rcvbufsize;
						break;
					case SO_SNDBUF:
						//printf("SO_SNDBUF\n");
						*(int *) optval =nl->sndbufsize;
						break;
				}
				break;
		}  /* switch */
		return 0;
	}
}

#endif   /* LWIP_NL */
