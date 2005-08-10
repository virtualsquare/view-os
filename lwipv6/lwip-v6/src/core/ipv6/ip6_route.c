/*
 * ip6_route.c routing table management IPv6
 * (IPv4 compatible using IPv4 prefixes).
 *
 *   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 * 
 * Copyright (c) 2004 Renzo Davoli
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "lwip/ip_route.h"
#include "lwip/inet.h"
#include "lwip/netlink.h"

static struct ip_route_list ip_route_pool[IP_ROUTE_POOL_SIZE];
static struct ip_route_list *ip_route_freelist;
static struct ip_route_list *ip_route_head;

void ip_route_list_init()
{
	register int i;
	for (i=0;i<IP_ROUTE_POOL_SIZE-1;i++)
		ip_route_pool[i].next=ip_route_pool+(i+1);
	ip_route_pool[i].next=NULL;
	ip_route_freelist=ip_route_pool;
	ip_route_head=NULL;
}

#define mask_wider(x,y) \
	(((y)->addr[0] & ~((x)->addr[0])) | \
	((y)->addr[1] & ~((x)->addr[1])) | \
	((y)->addr[2] & ~((x)->addr[2])) | \
	((y)->addr[3] & ~((x)->addr[3])))


err_t ip_route_list_add(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags)
{
	LWIP_ASSERT("ip_route_list_add NULL addr",addr != NULL);
	LWIP_ASSERT("ip_route_list_add NULL netmask",netmask != NULL);
	LWIP_ASSERT("ip_route_list_add NULL netif",netif != NULL);
	if(ip_route_freelist == NULL)
		return ERR_MEM;
	else {
		struct ip_route_list **dp=(&ip_route_head);
		struct ip_route_list *el=ip_route_freelist;
		ip_route_freelist=ip_route_freelist->next;
		ip_addr_set_mask(&(el->addr),addr,netmask);
		ip_addr_set(&(el->netmask),netmask);
		ip_addr_set(&(el->nexthop),nexthop);
		el->netif=netif;
		el->flags=flags;

		/* ordered insert */
		while (*dp != NULL && !mask_wider(&((*dp)->netmask),netmask)) {
			dp = &((*dp)->next);
		}
		el->next= *dp;
		*dp=el;
		/*printf("NEW ADDED!\n");
		ip_route_list_debug();*/
		return ERR_OK;
	}
}

err_t ip_route_list_del(struct ip_addr *addr, struct ip_addr *netmask, struct ip_addr *nexthop, struct netif *netif, int flags)
{
	struct ip_route_list **dp=(&ip_route_head);
	LWIP_ASSERT("ip_route_list_del NULL addr",addr != NULL);
	/*LWIP_ASSERT("ip_route_list_del NULL netmask",netmask != NULL);*/
	if (nexthop==NULL) nexthop=IP_ADDR_ANY;
	while (*dp != NULL && (
			!ip_addr_cmp(&((*dp)->addr),addr) ||
			(netmask != NULL && 
			 !ip_addr_cmp(&((*dp)->netmask),netmask)) ||
			( !ip_addr_cmp(&((*dp)->nexthop),nexthop) &&
			(*dp)->netif != netif )))
		dp = &((*dp)->next);
	if (*dp == NULL)
		return ERR_CONN;
	else {
		struct ip_route_list *el=*dp;
		*dp = el->next;
		el->next=ip_route_freelist;
		ip_route_freelist=el;
		return ERR_OK;
	}
}

err_t ip_route_list_delnetif(struct netif *netif)
{
	struct ip_route_list **dp=(&ip_route_head);
	if (netif == NULL)
		return ERR_OK;
	else {
		while (*dp != NULL) {
			if ((*dp)->netif == netif) {
				struct ip_route_list *el=*dp;
				*dp = el->next;
				el->next=ip_route_freelist;
				ip_route_freelist=el;
			} else
				dp = &((*dp)->next);
		}
	}
	return ERR_OK;
}

err_t ip_route_findpath(struct ip_addr *addr, struct ip_addr **pnexthop, struct netif **pnetif, int *flags)
{
	struct ip_route_list *dp=ip_route_head;
	LWIP_ASSERT("ip_route_findpath NULL addr",addr != NULL);
	LWIP_ASSERT("ip_route_findpath NULL pnetif",pnetif != NULL);
	LWIP_ASSERT("ip_route_findpath NULL pnexthop",pnexthop != NULL);
	while (dp != NULL &&
			!ip_addr_maskcmp(addr,&(dp->addr),&(dp->netmask))) 
		dp = dp->next;
	if (dp==NULL) {
		*pnetif=NULL;
		*pnexthop=NULL;
		return ERR_RTE;
	}
	else {
		*pnetif=dp->netif;
		if (ip_addr_isany(&(dp->nexthop)))
			*pnexthop=addr;
		else
			*pnexthop=&(dp->nexthop);
		/*if (ip_addr_isany(&(dp->nexthop)))
			printf("DIRECTLY CONNECTED %x\n",(*pnexthop)->addr[3]);
		else
			printf("VIA %x\n",(*pnexthop)->addr[3]);*/
		return ERR_OK;
	}
}

#if 0
void
ip_route_list_debug()
{
	struct ip_route_list *dp=ip_route_head;
	while (dp != NULL) {
		printf("addr %x:%x:%x:%x - msk %x:%x:%x:%x - nh %x:%x:%x:%x\n",
				dp->addr.addr[0],
				dp->addr.addr[1],
				dp->addr.addr[2],
				dp->addr.addr[3],
				dp->netmask.addr[0],
				dp->netmask.addr[1],
				dp->netmask.addr[2],
				dp->netmask.addr[3],
				dp->nexthop.addr[0],
				dp->nexthop.addr[1],
				dp->nexthop.addr[2],
				dp->nexthop.addr[3]);
		printf("addr%x- msk%x- nh%x\n",
				&(dp->addr),
				&(dp->netmask),
				&(dp->nexthop));
		dp=dp->next;
	}
}
#endif

#ifdef LWIP_NL
#include "lwip/netlink.h"

static int isdefault (struct ip_addr *addr)
{
	return 
		((addr->addr[0] | addr->addr[1] | addr->addr[2] | addr->addr[3] ) ==0)
		|| (ip_addr_is_v4comp(addr) && addr->addr[3] ==0);
}

void
ip_route_out_route_dst(int index,struct ip_route_list *irl,void * buf,int *offset)
{
	struct rtattr x;
	int isv4=ip_addr_is_v4comp(&(irl->addr));
	if (! isdefault(&(irl->addr))) {
		x.rta_len=sizeof(struct rtattr)+((isv4)?sizeof(u32_t):sizeof(struct ip_addr));
		x.rta_type=index;
		netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
		if (isv4)
			netlink_addanswer(buf,offset,&(irl->addr.addr[3]),sizeof(u32_t));
		else
			netlink_addanswer(buf,offset,&(irl->addr),sizeof(struct ip_addr));
	}
}

void
ip_route_out_route_gateway(int index,struct ip_route_list *irl,void * buf,int *offset)
{
	struct rtattr x;
	int isv4=ip_addr_is_v4comp(&(irl->addr));
	if (! isdefault(&(irl->nexthop))) {
		x.rta_len=sizeof(struct rtattr)+((isv4)?sizeof(u32_t):sizeof(struct ip_addr));
		x.rta_type=index;
		netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
		if (isv4)
			netlink_addanswer(buf,offset,&(irl->nexthop.addr[3]),sizeof(u32_t));
		else
			netlink_addanswer(buf,offset,&(irl->nexthop),sizeof(struct ip_addr));
	}
}

void
ip_route_out_route_oif(int index,struct ip_route_list *irl,void * buf,int *offset)
{
	struct rtattr x;
	u32_t id=irl->netif->id;
	x.rta_len=sizeof(struct rtattr)+sizeof(int);
	x.rta_type=index;
	netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
	netlink_addanswer(buf,offset,&(id),sizeof(u32_t));
}

typedef void (*opt_out_route)(int index,struct ip_route_list *ipl,void * buf,int *offset);

static opt_out_route ip_route_route_out_table[]={
	NULL,
	ip_route_out_route_dst,
	NULL, /*SRC*/
	NULL, /* IIF */
	ip_route_out_route_oif,
	ip_route_out_route_gateway,
	NULL,
	NULL};
#define IP_ROUTE_ROUTE_OUT_TABLE_SIZE (sizeof(ip_route_route_out_table)/sizeof(opt_out_route))

static void ip_route_netlink_out_route(struct nlmsghdr *msg,struct ip_route_list *irl,char family,void * buf,int *offset)
{
	register int i;
	int myoffset=*offset;
	if (family == 0 ||
		family == (ip_addr_is_v4comp(&(irl->addr))?PF_INET:PF_INET6)) {
		(*offset) += sizeof (struct nlmsghdr);

		/*printf("UNO route %x\n",irl->addr.addr[3]);*/
		struct rtmsg rtm;
		rtm.rtm_family= ip_addr_is_v4comp(&(irl->addr))?PF_INET:PF_INET6; 
		rtm.rtm_dst_len=mask2prefix(&(irl->netmask))-(ip_addr_is_v4comp(&(irl->addr))?(32*3):0); 

		rtm.rtm_src_len=0;
		rtm.rtm_tos=0;
		rtm.rtm_table=RT_TABLE_MAIN;
		rtm.rtm_protocol=RTPROT_KERNEL;
		rtm.rtm_scope=RT_SCOPE_UNIVERSE;
		rtm.rtm_type=RTN_UNICAST;
		/*rtm.rtm_flags=irl->flags; */
		rtm.rtm_flags=0; 

		netlink_addanswer(buf,offset,&rtm,sizeof (struct rtmsg));

		for (i=0; i< IP_ROUTE_ROUTE_OUT_TABLE_SIZE;i++)
		/*for (i=0; i<7;i++)*/
		if (ip_route_route_out_table[i] != NULL)
			ip_route_route_out_table[i](i,irl,buf,offset);
		msg->nlmsg_flags = NLM_F_MULTI;
		msg->nlmsg_type = RTM_NEWROUTE;
		msg->nlmsg_len = *offset - myoffset;
		netlink_addanswer(buf,&myoffset,msg,sizeof (struct nlmsghdr));
	}
}

void ip_route_netlink_getroute(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct rtmsg *rtm=(struct rtmsg *)(msg+1);
	/*char *opt=(char *)(rtm+1);*/
	int lenrestore=msg->nlmsg_len;
	int flag=msg->nlmsg_flags;
	char family=0;
	/*printf("ip_route_netlink_getrotue\n");*/
	if (msg->nlmsg_len < sizeof (struct nlmsghdr)) {
		fprintf(stderr,"Netlink getlink error\n");
		/* XXX error packet */
		return;
	}
	if (msg->nlmsg_len > sizeof (struct nlmsghdr)) 
		family=rtm->rtm_family;
	if ((flag & NLM_F_DUMP) == NLM_F_DUMP) {
		struct ip_route_list *dp=ip_route_head;
		while (dp != NULL) {
			ip_route_netlink_out_route(msg,dp,family,buf,offset);
			dp=dp->next;
		}
	}
	msg->nlmsg_type = NLMSG_DONE;
	msg->nlmsg_flags = 0;
	msg->nlmsg_len = sizeof (struct nlmsghdr);
	netlink_addanswer(buf,offset,msg,sizeof (struct nlmsghdr));
	msg->nlmsg_len=lenrestore;
	/* ip_route_list_debug();*/
	/*printf("FAMILY=%d\n",family);*/

}

void ip_route_netlink_adddelroute(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct rtmsg *rtm=(struct rtmsg *)(msg+1);
	struct rtattr *opt=(struct rtattr *)(rtm+1);
	int size=msg->nlmsg_len - sizeof(struct rtmsg) - sizeof(struct rtmsg);
	struct ip_addr ipaddr,netmask,nexthop;
	int netid;
	struct netif *nip=NULL;
	int family;
	int err;
	int flags=0;

	/*printf("netif_netlink_adddelroute\n");*/
	if (msg->nlmsg_len < sizeof (struct nlmsghdr)) {
		fprintf(stderr,"Netlink add/deladdr error\n");
		netlink_ackerror(msg,-ENXIO,buf,offset);
		return;
	}

	/* XXX controls TABLE_MAIN TYPE_UNICAST */
	family=rtm->rtm_family;
	memcpy(&ipaddr,IP_ADDR_ANY,sizeof(struct ip_addr));
	memcpy(&nexthop,IP_ADDR_ANY,sizeof(struct ip_addr));
	prefix2mask((int)(rtm->rtm_dst_len)+(rtm->rtm_family == PF_INET?(32*3):0),&netmask);
	if (family==PF_INET)
		ipaddr.addr[2]=nexthop.addr[2]=IP64_PREFIX;
	while (RTA_OK(opt,size)) {
		switch(opt->rta_type) {
			case RTA_DST:
				/*printf("RTN_DST\n");*/
				if (rtm->rtm_family == PF_INET && opt->rta_len == 8) {
					ipaddr.addr[2]=IP64_PREFIX;
					ipaddr.addr[3]=(*((int *)(opt+1)));
				}
				else if (rtm->rtm_family == PF_INET6 && opt->rta_len == 20) {
					register int i;
					for (i=0;i<4;i++)
						ipaddr.addr[i]=(*(((int *)(opt+1))+i));
				}
				else {
					netlink_ackerror(msg,-EINVAL,buf,offset);
					return;
				}

				break;
			case RTA_GATEWAY:
				/*printf("RTN_GATEWAY\n");*/
				if (rtm->rtm_family == PF_INET && opt->rta_len == 8) {
					nexthop.addr[2]=IP64_PREFIX;
					nexthop.addr[3]=(*((int *)(opt+1)));
				}
				else if (rtm->rtm_family == PF_INET6 && opt->rta_len == 20) {
					register int i;
					for (i=0;i<4;i++)
						nexthop.addr[i]=(*(((int *)(opt+1))+i));
				}
				else {
					netlink_ackerror(msg,-EINVAL,buf,offset);
					return;
				}

				break;
			case RTA_OIF:
				/*printf("RTA_OIF\n");*/
				if ( opt->rta_len != 8) {
					netlink_ackerror(msg,-EINVAL,buf,offset);
					return;
				} else
				{
					netid=(*((int *)(opt+1)));
					nip=netif_find_id(netid);
					if (nip == NULL) {
						fprintf(stderr,"Route add/deladdr id error %d \n",netid);
						netlink_ackerror(msg,-ENODEV,buf,offset);
						return;
					}

				}
				break;
			default:
				printf("Netlink: Unsupported RTA opt %d\n",opt->rta_type);
				break;
		}
		opt=RTA_NEXT(opt,size);
	}

	if (nip==NULL) {
		/* XXX search the interface */
		nip=netif_find_direct_destination(&nexthop);
	}
	if (nip == NULL) {
		fprintf(stderr,"Gateway unreachable\n");
		netlink_ackerror(msg,-ENETUNREACH,buf,offset);
		return;
	}

	if (msg->nlmsg_type == RTM_NEWROUTE) {
		err=ip_route_list_add(&ipaddr,&netmask,&nexthop,nip,flags);
	} else {
		err=ip_route_list_del(&ipaddr,&netmask,&nexthop,nip,flags);
	}
	/* XXX convert error */
	netlink_ackerror(msg,err,buf,offset);
}

#endif
