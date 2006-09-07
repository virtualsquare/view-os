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
#include "lwip/debug.h"
#include "lwip/opt.h"

#include "lwip/ip_route.h"
#include "lwip/inet.h"
#include "lwip/netlink.h"

/*--------------------------------------------------------------------------*/

//#ifndef ROUTE_DEBUG
//#define ROUTE_DEBUG  DBG_OFF
//#endif

/* added by Diego Billi */
#if 0
#ifdef IPv6_PMTU_DISCOVERY
static void ip_pmtu_init();
static void ip_pmtu_free_list(struct pmtu_info  *head);
#define IP_PMTU_FREELIST(list) \
	do {
		if ((list) != NULL) {            \
			ip_pmtu_free_list( (list) ); \
			(list) = NULL;               \
		}                                
	} while (0);
#endif
#endif


static struct ip_route_list ip_route_pool[IP_ROUTE_POOL_SIZE];
static struct ip_route_list *ip_route_freelist;
struct ip_route_list *ip_route_head;

/*---------------------------------------------------------------------------*/

#ifdef ROUTE_DEBUG

INLINE static void 
sprintf_ip(char *str, struct ip_addr *addr)
{
	if (addr != NULL) {

		sprintf(str, "%lx:%lx:%lx:%lx:%lx:%lx:",
			ntohl(addr->addr[0]) >> 16 & 0xffff,
			ntohl(addr->addr[0]) & 0xffff,
			ntohl(addr->addr[1]) >> 16 & 0xffff,
			ntohl(addr->addr[1]) & 0xffff,
			ntohl(addr->addr[2]) >> 16 & 0xffff,
			ntohl(addr->addr[2]) & 0xffff);

		str += strlen(str);
		
		if(ip_addr_is_v4comp(addr)) 
			sprintf(str, "%ld.%ld.%ld.%ld",
				ntohl(addr->addr[3]) >> 24 & 0xff,
				ntohl(addr->addr[3]) >> 16 & 0xff,
				ntohl(addr->addr[3]) >> 8 & 0xff,
				ntohl(addr->addr[3]) & 0xff);
		else {
			sprintf(str, "%lx:%lx",
				ntohl(addr->addr[3]) >> 16 & 0xffff,
				ntohl(addr->addr[3]) & 0xffff);
		}
	}
}


void ip_route_debug_list(void)
{
	char ip_tmp[40];
	struct ip_route_list *r = ip_route_head;

	if (r != NULL)
		LWIP_DEBUGF(ROUTE_DEBUG, ("Destination                             Gateway                                 Genmask                                 Iface\n"));
	while (r != NULL)	{
		sprintf_ip(ip_tmp, &r->addr);
		LWIP_DEBUGF(ROUTE_DEBUG, ("%-40s", ip_tmp)); sprintf_ip(ip_tmp, &r->nexthop);
		LWIP_DEBUGF(ROUTE_DEBUG, ("%-40s", ip_tmp)); sprintf_ip(ip_tmp, &r->netmask);
		LWIP_DEBUGF(ROUTE_DEBUG, ("%-40s", ip_tmp)); 
		LWIP_DEBUGF(ROUTE_DEBUG, ("%d (%c%c%d)", r->netif->id, r->netif->name[0],r->netif->name[1],r->netif->num));
		LWIP_DEBUGF(ROUTE_DEBUG, ("\n"));
		r = r->next;	
	}	
}
#else
#define ip_route_debug_list() {}
#endif

/*---------------------------------------------------------------------------*/

void ip_route_policy_table_init(void);


void ip_route_list_init(void)
{
	register int i;
	for (i=0;i<IP_ROUTE_POOL_SIZE-1;i++)
		ip_route_pool[i].next=ip_route_pool+(i+1);
	ip_route_pool[i].next=NULL;
	ip_route_freelist=ip_route_pool;
	ip_route_head=NULL;

#if 0
#ifdef IPv6_PMTU_DISCOVERY
	ip_pmtu_init();
#endif
#endif

	ip_route_policy_table_init();
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

		/* Find duplicate */
		while (*dp != NULL && 
			((!ip_addr_cmp(&((*dp)->addr),addr)) || 
				(!ip_addr_cmp(&((*dp)->netmask),netmask)) ||
				(!ip_addr_cmp(&((*dp)->nexthop),nexthop) && (*dp)->netif != netif)) )
			dp = &((*dp)->next);
	
		if (*dp != NULL)
			return ERR_CONN;

		
		dp=(&ip_route_head);

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

		ip_route_debug_list();

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
			(netmask != NULL && !ip_addr_cmp(&((*dp)->netmask),netmask)) ||
			( !ip_addr_cmp(&((*dp)->nexthop),nexthop) && (*dp)->netif != netif ) 
			))
		dp = &((*dp)->next);

	if (*dp == NULL)
		return ERR_CONN;
	else {
		struct ip_route_list *el=*dp;
		*dp = el->next;
#if 0
#ifdef IPv6_PMTU_DISCOVERY
		IP_PMTU_FREELIST( el->pmtu_list );
#endif
#endif

		el->next=ip_route_freelist;
		ip_route_freelist=el;

		ip_route_debug_list();

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

#if 0
#ifdef IPv6_PMTU_DISCOVERY
				IP_PMTU_FREELIST( el->pmtu_list );
#endif
#endif

				el->next=ip_route_freelist;
				ip_route_freelist=el;
			} else
				dp = &((*dp)->next);
		}

		ip_route_debug_list();
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
		if (ip_addr_isany(&(dp->nexthop))) {
			//LWIP_DEBUGF(ROUTE_DEBUG, ("DIRECTLY CONNECTED %x\n",(*pnexthop)->addr[3]));
			*pnexthop=addr;
		} else {
			//LWIP_DEBUGF(ROUTE_DEBUG, ("VIA %x\n",(*pnexthop)->addr[3]));
			*pnexthop=&(dp->nexthop);
		}

		return ERR_OK;
	}
}


#if LWIP_NL

/*---------------------------------------------------------------------------------*/
/* Netlink functions (iproute2 tools) */
/*---------------------------------------------------------------------------------*/

#include "lwip/netlink.h"

static int isdefault (struct ip_addr *addr)
{
	return 
		((addr->addr[0] | addr->addr[1] | addr->addr[2] | addr->addr[3] ) ==0)
		|| (ip_addr_is_v4comp(addr) && addr->addr[3] ==0);
}

void
ip_route_out_route_dst(int index,struct ip_route_list *irl,struct ip_addr *address,void * buf,int *offset)
{
	struct rtattr x;
	int isv4=ip_addr_is_v4comp(&(irl->addr));
	if (!address)
		address=&(irl->addr);
	if (! isdefault(address)) {
		x.rta_len=sizeof(struct rtattr)+((isv4)?sizeof(u32_t):sizeof(struct ip_addr));
		x.rta_type=index;
		netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
		if (isv4)
			netlink_addanswer(buf,offset,&(address->addr[3]),sizeof(u32_t));
		else
			netlink_addanswer(buf,offset,address,sizeof(struct ip_addr));
	}
}

void
ip_route_out_route_prefsrc(int index,struct ip_route_list *irl,struct ip_addr *address,void * buf,int *offset)
{
	struct rtattr x;
	int isv4=ip_addr_is_v4comp(&(irl->addr));
	struct ip_addr *directaddr;
	if (address) {
		if (! isdefault(&(irl->addr))) 
			directaddr= &(irl->addr);
		else 
			directaddr= &(irl->nexthop);
		if (directaddr) {
			struct ip_addr_list *srclist;

			if (isv4) 
				srclist=ip_addr_list_maskfind(irl->netif->addrs,directaddr);
			else
				srclist=ip_route_ipv6_select_source(irl->netif,directaddr);

			if(srclist) {
				x.rta_len=sizeof(struct rtattr)+((isv4)?sizeof(u32_t):sizeof(struct ip_addr));
				x.rta_type=index;
				netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
				if (isv4)
					netlink_addanswer(buf,offset,&(srclist->ipaddr.addr[3]),sizeof(u32_t));
				else
					netlink_addanswer(buf,offset,&(srclist->ipaddr),sizeof(struct ip_addr));
			}
		}
	}
}

void
ip_route_out_route_gateway(int index,struct ip_route_list *irl,struct ip_addr *address,void * buf,int *offset)
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
ip_route_out_route_oif(int index,struct ip_route_list *irl,struct ip_addr *address,void * buf,int *offset)
{
	struct rtattr x;
	u32_t id=irl->netif->id;
	x.rta_len=sizeof(struct rtattr)+sizeof(int);
	x.rta_type=index;
	netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
	netlink_addanswer(buf,offset,&(id),sizeof(u32_t));
}

typedef void (*opt_out_route)(int,struct ip_route_list *,struct ip_addr *,void *,int *);

static opt_out_route ip_route_route_out_table[]={
	NULL,
	ip_route_out_route_dst,
	NULL, 
	NULL, /* IIF */
	ip_route_out_route_oif,
	ip_route_out_route_gateway,
	NULL,
	ip_route_out_route_prefsrc};
#define IP_ROUTE_ROUTE_OUT_TABLE_SIZE (sizeof(ip_route_route_out_table)/sizeof(opt_out_route))

static void ip_route_netlink_out_route(struct nlmsghdr *msg,struct ip_route_list *irl,char family,struct ip_addr *address,struct ip_addr *netmask, void * buf,int *offset)
{
	register int i;
	int myoffset=*offset;
	if (family == 0 ||
		family == (ip_addr_is_v4comp(&(irl->addr))?PF_INET:PF_INET6)) {
		(*offset) += sizeof (struct nlmsghdr);

		/*printf("UNO route %x\n",irl->addr.addr[3]);*/
		struct rtmsg rtm;
		rtm.rtm_family= ip_addr_is_v4comp(&(irl->addr))?PF_INET:PF_INET6; 
		if (netmask)
			rtm.rtm_dst_len=mask2prefix(netmask)-(ip_addr_is_v4comp(&(irl->addr))?(32*3):0); 
		else
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
			if (ip_route_route_out_table[i] != NULL)
				ip_route_route_out_table[i](i,irl,address,buf,offset);
		msg->nlmsg_flags = NLM_F_MULTI;
		msg->nlmsg_type = RTM_NEWROUTE;
		msg->nlmsg_len = *offset - myoffset;
		netlink_addanswer(buf,&myoffset,msg,sizeof (struct nlmsghdr));
	}
}

void ip_route_netlink_getroute(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct rtmsg *rtm=(struct rtmsg *)(msg+1);
	struct rtattr *opt=(struct rtattr *)(rtm+1);
	int size=msg->nlmsg_len - sizeof(struct nlmsghdr) - sizeof(struct rtmsg);
	int lenrestore=msg->nlmsg_len;
	int flag=msg->nlmsg_flags;
	char family=0;
	/*printf("ip_route_netlink_getrotue %x\n",flag);*/
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
			ip_route_netlink_out_route(msg,dp,family,NULL,NULL,buf,offset);
			dp=dp->next;
		}
	} else if (size > 0){
		struct ip_addr ipaddr,netmask;
		struct ip_route_list *dp=ip_route_head;
		memcpy(&ipaddr,IP_ADDR_ANY,sizeof(struct ip_addr));
		prefix2mask((int)(rtm->rtm_dst_len)+(rtm->rtm_family == PF_INET?(32*3):0),&netmask);
		while (RTA_OK(opt,size)) {
			switch(opt->rta_type) {
				case RTA_DST:
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

				default:
					printf("Netlink: Unsupported RTA opt %d\n",opt->rta_type);
					break;
			}
			opt=RTA_NEXT(opt,size);
		}
		while (dp != NULL &&
				!ip_addr_maskcmp(&ipaddr,&(dp->addr),&(dp->netmask))) 
			dp = dp->next;
		if (dp != NULL) 
			ip_route_netlink_out_route(msg,dp,family,&ipaddr,&netmask,buf,offset);
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
	int size=msg->nlmsg_len - sizeof(struct nlmsghdr) - sizeof(struct rtmsg);
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



/*---------------------------------------------------------------------------------*/
/* IPv6 Default Address Selection (RFC 3484) */
/*---------------------------------------------------------------------------------*/



//#ifndef IPv6_ADDRSELECT_DBG
//#define IPv6_ADDRSELECT_DBG  DBG_OFF
//#endif


struct ip_policy {
	struct ip_addr ip;
	struct ip_addr prefix;
	u16_t          precedence;
	u16_t          label;
};

#define IP_SELECT_SRC_TABLE_SIZE   5

struct ip_policy  ip_policy_table[IP_SELECT_SRC_TABLE_SIZE];


/* FIX: now the table is read only, make it writable! */

/* FIX: add destination address selection */


void 
ip_route_policy_table_init(void)
{
	/* From RFC
      Prefix        Precedence Label
      ::1/128               50     0
      ::/0                  40     1
      2002::/16             30     2
      ::/96                 20     3
      ::ffff:0:0/96         10     4
	*/

	IP6_ADDR( &ip_policy_table[0].ip     , 0,0,0,0,0,0,0,1);
	IP6_ADDR( &ip_policy_table[0].prefix , 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0xffff);
	ip_policy_table[0].precedence = 50;
	ip_policy_table[0].label      =  0;

	IP6_ADDR( &ip_policy_table[1].ip     , 0,0,0,0,0,0,0,0);
	IP6_ADDR( &ip_policy_table[1].prefix , 0,0,0,0,0,0,0,0);
	ip_policy_table[0].precedence = 40;
	ip_policy_table[0].label      =  1;

	IP6_ADDR( &ip_policy_table[2].ip     , 0x2002,0,0,0,0,0,0,0);
	IP6_ADDR( &ip_policy_table[2].prefix , 0xffff,0,0,0,0,0,0,0);
	ip_policy_table[0].precedence = 30;
	ip_policy_table[0].label      =  2;

	IP6_ADDR( &ip_policy_table[3].ip     , 0,0,0,0,0,0,0,0);
	IP6_ADDR( &ip_policy_table[3].prefix , 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0,0);
	ip_policy_table[0].precedence = 20;
	ip_policy_table[0].label      =  3;

	IP6_ADDR( &ip_policy_table[4].ip     , 0,0,0,0,0,0xffff,0,0);
	IP6_ADDR( &ip_policy_table[4].prefix , 0xffff,0xffff,0xffff,0xffff,0xffff,0xffff,0,0);
	ip_policy_table[0].precedence = 10;
	ip_policy_table[0].label      =  4;

	LWIP_DEBUGF(ROUTE_DEBUG, ("%s: done\n", __func__));
}

u16_t  ip_policy_get_label(struct ip_addr *ip)
{
	int i;

	for (i=0; i < IP_SELECT_SRC_TABLE_SIZE; i++) {
		if (ip_addr_maskcmp(ip, &ip_policy_table[i].ip, &ip_policy_table[i].prefix)) {
			return ip_policy_table[i].label;
		}
	}
	return 0;
}

#define SCOPE_NODE   0x1
#define SCOPE_LINK   0x2 
#define SCOPE_SUBNET 0x3 
#define SCOPE_ADMIN  0x4
#define SCOPE_SITE   0x5
#define SCOPE_ORG    0x8 
#define SCOPE_GLOBAL 0xE
#define ismulticast(addr1,scope) ( (ntohl((addr1)->addr[0]) & 0x000f) == (scope) )

#define isunicast_link(addr1)    (ntohl((addr1)->addr[0]) & 0xFE80)
#define isunicast_site(addr1)    (ntohl((addr1)->addr[0]) & 0xFEC0)
#define isunicast_global(addr1)  (ntohl((addr1)->addr[0]) & 0x2000)

INLINE static int ip_policy_get_scope(struct ip_addr *ip)
{
	/* FIX: do this better */
	if (ip_addr_ismulticast(ip)) {
		if (ismulticast(ip,SCOPE_NODE))   return 0;
		if (ismulticast(ip,SCOPE_LINK))   return 1;
		if (ismulticast(ip,SCOPE_SUBNET)) return 2;
		if (ismulticast(ip,SCOPE_ADMIN))  return 3;
		if (ismulticast(ip,SCOPE_SITE))   return 4;
		if (ismulticast(ip,SCOPE_ORG))    return 5;
		if (ismulticast(ip,SCOPE_GLOBAL)) return 6;
	}
	else {
		if (isunicast_link(ip))           return 1;
		if (isunicast_site(ip))           return 4;
		if (isunicast_global(ip))         return 6;
	}

	/* Strange, return the smallest scope */
	LWIP_DEBUGF(ROUTE_DEBUG, ("%s: unable to get address scope. BUG?\n", __func__));
	return 0;
}

INLINE static struct ip_addr_list * 
select_prefer_source(struct ip_addr_list *sa, struct ip_addr_list *sb, struct ip_addr *dst, struct netif *outif)
{
	int scope_sa, scope_sb, scope_d;
	int label_sa, label_sb, label_d;

	/* FIX: implement all checks */

	/* Rule 1:  Prefer same address.
	If SA = D, then prefer SA.  Similarly, if SB = D, then prefer SB. */
	if (ip_addr_cmp(&(sa->ipaddr), dst)) 
		return sa; 
	else 
	if (ip_addr_cmp(&(sb->ipaddr), dst)) 
		return sb; 
	
	/* Rule 2:  Prefer appropriate scope.
	If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D), then prefer SB
	and otherwise prefer SA.  Similarly, if Scope(SB) < Scope(SA): If
	Scope(SB) < Scope(D), then prefer SA and otherwise prefer SB. */
	scope_sa = ip_policy_get_scope(&sa->ipaddr);
	scope_sb = ip_policy_get_scope(&sb->ipaddr);
	scope_d  = ip_policy_get_scope(dst);

	if (scope_sa < scope_sb) {
		if (scope_sa < scope_d) return sb; 
		else                    return sa; 
	} else
	if (scope_sb < scope_sa) {
		if (scope_sb < scope_d) return sa; 
		else                    return sb; 
	}
	
	/* Rule 3:  Avoid deprecated addresses.
	The addresses SA and SB have the same scope.  If one of the two
	source addresses is "preferred" and one of them is "deprecated" (in
	the RFC 2462 sense), then prefer the one that is "preferred." */
#if IPv6_AUTO_CONFIGURATION
	if (sa->info.flag != IPADDR_PREFERRED)
		if (sb->info.flag == IPADDR_PREFERRED) 
			return sb;
	if (sb->info.flag != IPADDR_PREFERRED)
		if (sa->info.flag == IPADDR_PREFERRED) 
			return sa;
#endif
	
	/* Rule 4:  Prefer home addresses.
	If SA is simultaneously a home address and care-of address and SB is
	not, then prefer SA.  Similarly, if SB is simultaneously a home
	address and care-of address and SA is not, then prefer SB.
	If SA is just a home address and SB is just a care-of address, then
	prefer SA.  Similarly, if SB is just a home address and SA is just a
	care-of address, then prefer SB.  */
	/* Implementations should provide a mechanism allowing an application to
	reverse the sense of this preference and prefer care-of addresses
	over home addresses (e.g., via appropriate API extensions).  Use of
	the mechanism should only affect the selection rules for the invoking
	application. */

	/* TODO */
	
	/* Rule 5:  Prefer outgoing interface.
	If SA is assigned to the interface that will be used to send to D
	and SB is assigned to a different interface, then prefer SA.
	Similarly, if SB is assigned to the interface that will be used to
	send to D and SA is assigned to a different interface, then prefer
	SB. */

	/* TODO: up to now, selected SA and SB are both assigned to the interface */
	
	/* Rule 6:  Prefer matching label.
	If Label(SA) = Label(D) and Label(SB) <> Label(D), then prefer SA.
	Similarly, if Label(SB) = Label(D) and Label(SA) <> Label(D), then
	prefer SB. */
	label_sa = ip_policy_get_label(&sa->ipaddr);
	label_sb = ip_policy_get_label(&sb->ipaddr);
	label_d  = ip_policy_get_label(dst);
	if (label_sa == label_d && label_sb != label_d) {
		return sa; 
	}
	if (label_sb == label_d && label_sa != label_d) {
		return sb;
	}

	/* Rule 7:  Prefer public addresses.
	If SA is a public address and SB is a temporary address, then prefer
	SA.  Similarly, if SB is a public address and SA is a temporary
	address, then prefer SB. */

	/* TODO */

	/* Rule 8:  Use longest matching prefix.
	If CommonPrefixLen(SA, D) > CommonPrefixLen(SB, D), then prefer SA.
	Similarly, if CommonPrefixLen(SB, D) > CommonPrefixLen(SA, D), then
	prefer SB. */

	/* TODO */
	
	/* Rule 8 may be superseded if the implementation has other means of
	choosing among source addresses.  For example, if the implementation
	somehow knows which source address will result in the "best"
	communications performance. */
	
	/* Rule 2 (prefer appropriate scope) MUST be implemented and given high
	priority because it can affect interoperability. */

	
	/* Uhm... just choose one of them */

	return sa;
}

struct ip_addr_list * ip_route_ipv6_select_source(struct netif *outif, struct ip_addr *dst)
{
    struct ip_addr_list *el, *tail;
	struct ip_addr_list *sa, *sb;
	struct ip_addr_list *prefer;

	LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, ("%s:  destination ip=", __func__));
		ip_addr_debug_print(IPv6_ADDRSELECT_DBG, dst);
		LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, ("\n"));

	/* RFC 3484 - 4. Candidate Source Addresses
	[...]It is RECOMMENDED that the candidate source addresses be the set of
	unicast addresses assigned to the interface that will be used to send
	to the destination.  (The "outgoing" interface.)  On routers, the
	candidate set MAY include unicast addresses assigned to any interface
	that forwards packets, subject to the restrictions described below[...]
	*/

    /* Visit interface's addresses and take the prefered one */
	prefer = sa = sb = NULL;
	el = tail = outif->addrs->next;
	do {
		sa = prefer;
	    /* Get SA (skip IPv4) */
		if (sa == NULL)
			if (!ip_addr_is_v4comp(&el->ipaddr)) 
				sa = el;
		/* Get SB (skip ipv4) */
		if (!ip_addr_is_v4comp(&el->ipaddr))
			sb = el;

		/* If sa != sb != NULL, they are IPv6 and i can compare them */
		if (sa != NULL && sb != NULL) {
			if (sa != sb)
				prefer = select_prefer_source(sa, sb, dst, outif);
			else
				prefer = sa;
		}

		el=el->next;
	} while (el != tail);

#if IPv6_ADDRSELECT_DBG == DBG_ON
	LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, ("%s:  ", __func__));
	ip_addr_debug_print(IPv6_ADDRSELECT_DBG, &sa->ipaddr);
	LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, (", "));
	ip_addr_debug_print(IPv6_ADDRSELECT_DBG, &sb->ipaddr);
	LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, (" -> "));
	ip_addr_debug_print(IPv6_ADDRSELECT_DBG, &prefer->ipaddr);
	LWIP_DEBUGF(IPv6_ADDRSELECT_DBG, ("\n"));
#endif

	return prefer;
}









/* added by Diego Billi */
#if 0

/*---------------------------------------------------------------------------------*/
/* Path MTU Discovery - RFC 1191, 1981(ipv6) */
/*---------------------------------------------------------------------------------*/

err_t pmtu_find_route_entry(struct ip_addr *dest, struct ip_route_list **entry)
{
	struct ip_route_list *r = ip_route_head;

	while (r != NULL) {
		if (ip_addr_maskcmp(dest, &(r->addr), &(r->netmask)))
			break;
 
		r = r->next;
	}

	if (r !=NULL) {
		*entry = r;
		return ERR_OK;
	}
	return ERR_RTE;
}



#ifdef IPv6_PMTU_DISCOVERY

/* NOT TESTED YET, NOT TESTED YET, NOT TESTED YET, NOT TESTED YET  */

/* 
 * Here follows a simple implementation of Path MTU Discovery 
 * protocol (RFC 1191). 
 */

/* 
 * This table contains commont internet MTUs used by the MTU Detection
 * algorithm described in the section 7.1. of RFC 1191 (where you can
 * also find the original table).
 */

#ifndef PMTU_DEBUG
#define PMTU_DEBUG  DBG_OFF
#endif



#define IP_COMMONS_MTUS 11
u16_t ip_pmtu_common_mtus[IP_COMMONS_MTUS] = {
	68, 296, 508, 1006, 1492, 2002, 4352, 8166, 17914, 32000, 65535
};

#define IP_PMTU_DEST_POOL_SIZE   128
static struct pmtu_info  ip_pmtu_pool[IP_PMTU_DEST_POOL_SIZE];
static struct pmtu_info  *ip_pmtu_freelist;
static struct pmtu_info  *ip_pmtu_head;  /* main list */

static void ip_pmtu_start_timer(void);

static void ip_pmtu_init()
{
	register int i;

	/* Clear table & lists */
	for (i=0;i<IP_PMTU_DEST_POOL_SIZE-1;i++)
		ip_pmtu_pool[i].next = ip_pmtu_pool + (i+1);
	ip_pmtu_pool[i].next = NULL;

	ip_pmtu_freelist  = ip_pmtu_pool;
	ip_pmtu_head = NULL;

	ip_pmtu_start_timer();
}

static void ip_pmtu_free_list(struct pmtu_info  *head)
{
	struct pmtu_info  *last;

	/* go to end */
	last = head;
	while (last->next != NULL)
		last = last->next;

	last->next = ip_pmtu_freelist;
	ip_pmtu_freelist = head;
}

/* Increase 'mtu' to the first greater internet's MTU */
void pmtu_increase(struct pmtu_info  *p, u16_t defval)
{
	int i; 

	p->pmtu = defval;

	/* Find the first MTU greater than 'p->pmtu' */
	for (i=0; i < IP_COMMONS_MTUS; i++) 
		if ( p->pmtu < ip_pmtu_common_mtus[i]) { 
			p->pmtu = ip_pmtu_common_mtus[i]; 
			break; 
		} 
}

err_t ip_pmtu_add(struct ip_addr *src, struct ip_addr *dest, u8_t tos, u16_t mtu)
{
	if (ip_pmtu_freelist == NULL)
		return ERR_MEM;
	else {
		struct ip_route_list *entry;
		struct pmtu_info **dp = (&ip_pmtu_head);
		struct pmtu_info  *el = ip_pmtu_freelist;

		LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_add: new entry"));
		LWIP_DEBUGF(PMTU_DEBUG, ("[src=")); ip_addr_debug_print(PMTU_DEBUG, src);
		LWIP_DEBUGF(PMTU_DEBUG, (" dest=")); ip_addr_debug_print(PMTU_DEBUG, dest);
		LWIP_DEBUGF(PMTU_DEBUG, (" tos=%d", tos));
		LWIP_DEBUGF(PMTU_DEBUG, (" mtu=%d]\n", mtu));

		/* If we find a route entry in the routing which matches 
		   destination address */
		if (pmtu_find_route_entry(dest, &entry) == ERR_OK) {

			/* Get new PMTU descriptor */
			ip_pmtu_freelist = ip_pmtu_freelist->next;
			el->next = *dp;
			*dp      = el;

			/* Save Path MTU informations */
			ip_addr_set( &el->dest, dest );
			ip_addr_set( &el->src , src  );
			el->tos       = tos;
			el->pmtu      = mtu;

			/* Just created. Start PMTU Increase later */
			el->op_timeout = PMTU_INCREASE_TIMEOUT; 
			el->flags      = PMTU_FLAG_INCREASE;

			/* this entry is new */
			el->expire_time = 0; 
			
			/* Add PMTU informations in the route entry */
			el->next = entry->pmtu_list;
			entry->pmtu_list = el;

			LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_add: added.\n"));
			return ERR_OK;
		}
		else {
			LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_add: not found route\n"));
			return ERR_RTE;
		}
	}
}

static inline err_t ip_pmtu_findinfo(struct ip_addr *dest, struct ip_addr *src, u8_t tos, struct pmtu_info **p)
{
	struct ip_route_list *entry;

	if (pmtu_find_route_entry(dest, &entry) == ERR_OK) {

		/* Search */
		struct pmtu_info *i = entry->pmtu_list;
		while (i != NULL) {

			if (ip_addr_cmp(&i->dest, dest) && ip_addr_cmp(&i->src, src) && (i->tos == tos))
				break;

			i = i->next;
		}

		if (i != NULL) {
			*p = i;
			return ERR_OK;
		}
		LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_findinfo: entry not found "));
		LWIP_DEBUGF(PMTU_DEBUG, ("[src=")); ip_addr_debug_print(PMTU_DEBUG, src);
		LWIP_DEBUGF(PMTU_DEBUG, (" dest=")); ip_addr_debug_print(PMTU_DEBUG, dest);
		LWIP_DEBUGF(PMTU_DEBUG, (" tos=%d]\n", tos));

		*p = NULL;		
		return ERR_RTE;
	}
	else {
		LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_findinfo: ______________ROUTE ENTRY NOT FOUND_______________ "));	
	}
	return ERR_RTE;
}

err_t ip_pmtu_getmtu(struct ip_addr *dest, struct ip_addr *src, u8_t tos, u16_t *mtu)
{
	struct pmtu_info *i=NULL;

	/* find pmtu info */
	if (ip_pmtu_findinfo(dest, src, tos, &i) == ERR_OK) {
		*mtu = i->pmtu;
		/* Reset expire time */
		i->expire_time = 0;
		return ERR_OK;
	}
	return ERR_RTE;
}

err_t ip_pmtu_decrease(struct ip_addr *dest, struct ip_addr *src, u8_t tos, u16_t new_mtu)
{
	struct pmtu_info *i=NULL;

	/* find pmtu info */
	if (ip_pmtu_findinfo(dest, src, tos, &i) == ERR_OK) {
		LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_decrease: decreased "));
		LWIP_DEBUGF(PMTU_DEBUG, ("[src=")); ip_addr_debug_print(PMTU_DEBUG, &i->src);
		LWIP_DEBUGF(PMTU_DEBUG, (" dest=")); ip_addr_debug_print(PMTU_DEBUG, &i->dest);
		LWIP_DEBUGF(PMTU_DEBUG, (" tos=%d", i->tos));
		LWIP_DEBUGF(PMTU_DEBUG, (" mtu=%d] ", i->pmtu));
		LWIP_DEBUGF(PMTU_DEBUG, ("downto %d\n", new_mtu ));

		if (i->pmtu < new_mtu)
			LWIP_DEBUGF(PMTU_DEBUG, ("ip_pmtu_decrease: ***WARNING*** pmtu(%d) > decremented mtu(%d) \n", i->pmtu, new_mtu ));

		i->pmtu = new_mtu;

		/* Reset expire time */
		i->expire_time = 0;

		/* Wait a while before increase again Path MTU */					
		i->op_timeout = PMTU_INCREASE_TIMEOUT;
		i->flags      = PMTU_FLAG_INCREASE;

		/*
         * TODO: notify Transport Level (TCP/UDP)
         */

		return ERR_OK;
	}
	return ERR_RTE;
}


/* Called every  minute. Visits routing table:
 *   - remove unused pmtu_info 
 *   - increase Path MTU
 *   - restore PathMTU to the next-hop's mtu
 */
static inline void pmtu_tmr(void)
{
	struct ip_route_list *r;
	struct pmtu_info **i;
	struct pmtu_info *removed;

	r  = ip_route_head;
	while (r != NULL) { 

		/* Check all per-host destination for this route */
		i = & r->pmtu_list;
		while (*i != NULL) {

			(*i)->expire_time++;

			/* First, clean garbage */
			if ((*i)->expire_time != PMTU_NEVER_EXPIRE) 
			if ((*i)->expire_time >= PMTU_EXPIRE_TIMEOUT) {
				LWIP_DEBUGF(PMTU_DEBUG, ("pmtu_timer: entry "));
				LWIP_DEBUGF(PMTU_DEBUG, ("[src=")); ip_addr_debug_print(PMTU_DEBUG, & (*i)->src);
				LWIP_DEBUGF(PMTU_DEBUG, (" dest=")); ip_addr_debug_print(PMTU_DEBUG, & (*i)->dest);
				LWIP_DEBUGF(PMTU_DEBUG, (" tos=%d", (*i)->tos));
				LWIP_DEBUGF(PMTU_DEBUG, (" mtu=%d] expired! \n", (*i)->pmtu));
				/* Adjust list pointers */
				removed = *i;
				*i = removed->next;

				/* TODO: notify Transport Layer (UDP/TCP) */

				/* add pmtu_info to the free list */
				removed->next = ip_pmtu_freelist;
				ip_pmtu_freelist = removed;
				continue;
			}

			/* Update operations timeout */
			(*i)->op_timeout --;

			if ((*i)->op_timeout == 0) {
				LWIP_DEBUGF(PMTU_DEBUG, ("pmtu_timer: timeout on entry"));
				LWIP_DEBUGF(PMTU_DEBUG, ("[src=")); ip_addr_debug_print(PMTU_DEBUG, & (*i)->src);
				LWIP_DEBUGF(PMTU_DEBUG, (" dest=")); ip_addr_debug_print(PMTU_DEBUG, & (*i)->dest);
				LWIP_DEBUGF(PMTU_DEBUG, (" tos=%d", (*i)->tos));
				LWIP_DEBUGF(PMTU_DEBUG, (" mtu=%d]\n", (*i)->pmtu));
				if ((*i)->flags == PMTU_FLAG_INCREASE) {
					pmtu_increase( (*i) , r->netif->mtu );
					LWIP_DEBUGF(PMTU_DEBUG, ("pmtu_timer: increased pmtu to %d >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n",(*i)->pmtu ));
					/* In the near future we could have to decrease mtu */					
					(*i)->op_timeout = PMTU_DECREASE_TIMEOUT;
					(*i)->flags      = PMTU_FLAG_DECREASE;

				} else 
				if ((*i)->flags == PMTU_FLAG_DECREASE) {
					/* Restore PathMTU to next-hop's mtu */
					(*i)->pmtu = r->netif->mtu;
					LWIP_DEBUGF(PMTU_DEBUG, ("pmtu_timer: decreased pmtu downto %d <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",(*i)->pmtu ));
					/* Wait a while before increase again Path MTU */					
					(*i)->op_timeout = PMTU_INCREASE_TIMEOUT;
					(*i)->flags      = PMTU_FLAG_INCREASE;
				}
			}
			i = &((*i)->next);
		}
		r = r->next;
	}
}

static void pmtu_timer_callback(void *arg)
{
	pmtu_tmr();

	sys_timeout(PMTU_TMR_INTERVAL, pmtu_timer_callback, NULL);
}

static void ip_pmtu_start_timer(void)
{
	sys_timeout(PMTU_TMR_INTERVAL, pmtu_timer_callback, NULL);
}

#endif


#endif /* IPv6_PMTU_DISCOVERY */


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





