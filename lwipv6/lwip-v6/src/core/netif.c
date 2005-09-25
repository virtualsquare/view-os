/**
 * @file
 *
 * lwIP network interface abstraction
 */

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
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/ip_addr.h"
#ifdef LWIP_NL
#include "lwip/api.h"
#include "lwip/sockets.h"
#include "lwip/netlink.h"
#endif
#include "lwip/ip_route.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/if.h"

struct netif *netif_list = NULL;

/**
 * Add a network interface to the list of lwIP netifs.
 *
 * @param netif a pre-allocated netif structure
 * @param ipaddr IP address for the new netif
 * @param netmask network mask for the new netif
 * @param state opaque data passed to the new netif
 * @param init callback function that initializes the interface
 * @param input callback function that is called to pass
 * ingress packets up in the protocol layer stack.
 *
 * @return netif, or NULL if failed.
 */
struct netif *
netif_add(struct netif *netif, void *state, err_t (* init)(struct netif *netif),
  err_t (* input)(struct pbuf *p, struct netif *netif))
{
  static u16_t uniqueid=0;
	struct netif *nip;
	struct netif *lastnip;
	for (nip=netif_list; nip!=NULL; lastnip=nip,nip=nip->next)
		;

#if LWIP_DHCP
  /* netif not under DHCP control by default */
  netif->dhcp = NULL;
#endif
  /* remember netif specific state information data */
  netif->state = state;
  netif->num = 0;
  netif->input = input;
  netif->addrs = NULL;
  netif->id = ++uniqueid;
  netif->flags = NETIF_RUNNING;
  /* printf("netif_add %x netif->input %x\n",netif,netif->input); */

  /* call user specified initialization function for netif */
  if (init(netif) != ERR_OK) {
    ip_addr_list_freelist(netif->addrs);
    return NULL;
  }

  if (netif_list == NULL)
	  netif_list = netif;
  else
	  lastnip->next=netif;
  netif->next=NULL;
  LWIP_DEBUGF(NETIF_DEBUG, ("netif: added interface %c%c%d\n",
    netif->name[0], netif->name[1], netif->num));
  printf("added interface %c%c%d\n",netif->name[0],netif->name[1],netif->num);
  return netif;
}

int
netif_add_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask)
{
/* XXX check if this address is compatible */
  struct ip_addr_list *add;

  if (ip_addr_list_find(netif->addrs, ipaddr, netmask) != NULL) {
	  LWIP_DEBUGF( NETIF_DEBUG, ("netif_add_addr: Address already exists\n") );
	  return -EADDRINUSE;
  } else {
	  add=ip_addr_list_alloc();
	  if (add==NULL) {
		  LWIP_DEBUGF( NETIF_DEBUG, ("netif_add_addr: NO more available addresses\n") );
	  	return -ENOMEM;
	  }
	  else {
		  ip_addr_set(&(add->ipaddr),ipaddr);
		  ip_addr_set(&(add->netmask),netmask);
		  add->flags=IFA_F_PERMANENT;
		  add->netif=netif;
		  ip_addr_list_add(&(netif->addrs),add);
		  ip_route_list_add(ipaddr,netmask,NULL,netif,0);
		  return 0;
	  }
  }
}

static void ip_addr_close(struct ip_addr *ipaddr)
{
#if LWIP_TCP
	 struct tcp_pcb *pcb;
	 /* struct tcp_pcb_listen *lpcb; */
	 pcb = tcp_active_pcbs;
	 while (pcb != NULL) {
		 /* PCB bound to current local interface address? */
		 if (ip_addr_cmp(&(pcb->local_ip), ipaddr)) {
			 /* this connection must be aborted */
			 struct tcp_pcb *next = pcb->next;
			 LWIP_DEBUGF(NETIF_DEBUG | 1, ("netif_addr_close: aborting TCP pcb %p\n", (void *)pcb));
			 tcp_abort(pcb);
			 pcb = next;
		 } else {
			 pcb = pcb->next;
		 }
	 }
#if 0
	 /* XXX TO BE managed */
	 for (lpcb = tcp_listen_pcbs.listen_pcbs; lpcb != NULL; lpcb = lpcb->next) {
		 /* PCB bound to current local interface address? */
		 if (ip_addr_cmp(&(lpcb->local_ip), &(netif->ip_addr))) {
			 /* The PCB is listening to the old ipaddr and
			  * is set to listen to the new one instead */
			 ip_addr_set(&(lpcb->local_ip), ipaddr);
		 }
	 }
#endif
#endif
}

int
netif_del_addr(struct netif *netif,struct ip_addr *ipaddr, struct ip_addr *netmask)
{
 struct ip_addr_list *el;

 if ((el=ip_addr_list_find(netif->addrs, ipaddr, netmask)) == NULL) {
	  LWIP_DEBUGF( NETIF_DEBUG, ("netif_del_addr: Address does not exist\n") );
	  return -ENXIO;

 } else
 {
	 ip_addr_close(ipaddr);
	 ip_route_list_del(ipaddr,netmask,NULL,netif,0);
	 ip_addr_list_del(&(netif->addrs),el);	 
	 return 0;
 }
}

void netif_remove(struct netif * netif)
{
  if ( netif == NULL ) return;

  /*  is it the first netif? */
  if (netif_list == netif) {
    netif_list = netif->next;
  }
  else {
    /*  look for netif further down the list */
    struct netif * tmpNetif;
    for (tmpNetif = netif_list; tmpNetif != NULL; tmpNetif = tmpNetif->next) {
      if (tmpNetif->next == netif) {
	struct ip_addr_list *el;
        tmpNetif->next = netif->next;
	while (netif->addrs != NULL) {
		el=ip_addr_list_first(netif->addrs);
		ip_addr_close(&(el->ipaddr));
		ip_addr_list_del(&(netif->addrs),el);
	}
        break;
        }
    }
    if (tmpNetif == NULL)
      return; /*  we didn't find any netif today */
  }
  ip_route_list_delnetif(netif);
  LWIP_DEBUGF( NETIF_DEBUG, ("netif_remove: removed netif\n") );
}

struct netif *
netif_find(char *name)
{
  struct netif *netif;
  u8_t num;

  if (name == NULL) {
    return NULL;
  }

  if (name[2] >= '0'  && name [2] <= '9')
		num = name[2] - '0';
	else
		num = 0;

  for(netif = netif_list; netif != NULL; netif = netif->next) {
    if (num == netif->num &&
       name[0] == netif->name[0] &&
       name[1] == netif->name[1]) {
      LWIP_DEBUGF(NETIF_DEBUG, ("netif_find: found %c%c\n", name[0], name[1]));
      return netif;
    }
  }
  LWIP_DEBUGF(NETIF_DEBUG, ("netif_find: didn't find %c%c\n", name[0], name[1]));
  return NULL;
}

struct netif *
netif_find_id(int id)
{
  struct netif *nip;

  for (nip=netif_list; nip!=NULL && nip->id != id; nip=nip->next)
	  ;

  return nip;
}

struct netif *
netif_find_direct_destination(struct ip_addr *addr)
{
	struct netif *nip;
	for (nip=netif_list;
			nip!=NULL && ip_addr_list_maskfind(nip->addrs,addr) == NULL;
			nip=nip->next)
		;
	return nip;
}

void
netif_init(void)
{
  ip_addr_list_init();
  ip_route_list_init();
  netif_list = NULL;
}

static int netif_ifconf(struct ifconf *ifc) 
{
	struct netif *nip;
	register int i;
#define ifr_v (ifc->ifc_req)

	/*printf("-netif_ifconf %d\n",ifc->ifc_len);*/
  	for (nip=netif_list, i=0; nip!=NULL && i<ifc->ifc_len; 
			nip=nip->next, i++) {
		ifr_v[i].ifr_name[0]=nip->name[0];
		ifr_v[i].ifr_name[1]=nip->name[1];
		ifr_v[i].ifr_name[2]=(nip->num%10)+'0';
		ifr_v[i].ifr_name[3]= 0;
		ifr_v[i].ifr_name[4]= 0;
		ifr_v[i].ifr_name[5]= 0;
	}
	ifc->ifc_len=i*sizeof(struct ifreq);
	/*{int i;
		printf("len %d %d\n",ifc->ifc_len,sizeof(struct ifreq));
		for (i=0;i<ifc->ifc_len;i++) {
			int c=*(((char *)(ifr_v))+i);
			printf("%02x%c ",c,(c>=' '&&c<='~')?c:'.');
			if (i%16 == 15)
				printf("\n");
		}
		if (i%16 != 15)
			printf("\n");
	}*/

	return ERR_OK;
#undef ifr_v
}

int netif_ioctl(int cmd,struct ifreq *ifr)
{
	int retval;
	struct netif *nip;
	register int i;
	//printf("netif_ioctl %x\n",cmd);
	if (ifr == NULL)
		retval=EFAULT;
	else {
		if (cmd == SIOCGIFCONF) {
			retval=netif_ifconf((struct ifconf *)ifr);
		} else {
#define ifrname ifr->ifr_name
			ifrname[4]=ifrname[5]=0;
			if (ifrname[3] != 0 ||
					(nip = netif_find(ifrname)) == NULL) {
				//printf("%s: interface not found\n",ifrname);
				retval=EINVAL;
			}
			else {
#undef ifrname
				switch (cmd) {
					case SIOCGIFFLAGS:
						ifr->ifr_flags= nip->flags & ~(IFF_RUNNING);
						/*printf("SIOCGIFFLAGS %x\n",nip->flags);*/
						retval=ERR_OK; break;
					case SIOCSIFFLAGS:
						nip->flags = (nip->flags & IFF_RUNNING) | (ifr->ifr_flags & ~(IFF_RUNNING));
						/*printf("SIOCSIFFLAGS %x %x\n",ifr->ifr_flags, nip->flags);*/
						retval=ERR_OK; break;

					case SIOCGIFMTU:
						ifr->ifr_mtu=nip->mtu;
						retval=ERR_OK; break;
					case SIOCSIFMTU:
						nip->mtu=ifr->ifr_mtu;
						retval=ERR_OK; break;

					case SIOCGIFHWADDR:
						ifr->ifr_hwaddr.sa_family=nip->type;
						for (i=0;i<nip->hwaddr_len;i++)
						ifr->ifr_hwaddr.sa_data[i]=nip->hwaddr[i];
						retval=ERR_OK; break;

					case SIOCGIFINDEX:
						ifr->ifr_ifindex=nip->id;
						retval=ERR_OK; break;

					default:
						retval=ENOSYS;
				}
			}
		}
	}
	return retval;
}

#ifdef LWIP_NL

static void netif_out_link_address (int index,struct netif *nip,void * buf,int *offset) {
	struct rtattr x;
	int fill=0;
	if (nip->hwaddr_len>0) {
		x.rta_len=sizeof(struct rtattr)+nip->hwaddr_len;
		x.rta_type=index;
		netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
		netlink_addanswer(buf,offset,nip->hwaddr,nip->hwaddr_len);
		if (nip->hwaddr_len % RTA_ALIGNTO > 0)
			netlink_addanswer(buf,offset,&fill,RTA_ALIGNTO - (nip->hwaddr_len % RTA_ALIGNTO));
	}
}

static void netif_out_link_broadcast (int index,struct netif *nip,void * buf,int *offset) {
	struct rtattr x;
	int fill=0;
	if (nip->hwaddr_len>0) {
		x.rta_len=sizeof(struct rtattr)+nip->hwaddr_len;
		x.rta_type=index;
		netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
		for (fill=0; fill<nip->hwaddr_len; fill++)
			netlink_addanswer(buf,offset,"\377",1);
		fill=0;
		if (nip->hwaddr_len % RTA_ALIGNTO > 0)
			netlink_addanswer(buf,offset,&fill,RTA_ALIGNTO - (nip->hwaddr_len % RTA_ALIGNTO));
	}
}

static void netif_out_link_ifname (int index,struct netif *nip,void * buf,int *offset) {
	struct rtattr x;
	char name[4];
	x.rta_len=sizeof(struct rtattr)+3;
	x.rta_type=index;
	netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
	name[0]=nip->name[0];
	name[1]=nip->name[1];
	name[2]=(nip->num)%10+'0';
	name[3]=0;
	netlink_addanswer(buf,offset,name,sizeof(name));
}

static void netif_out_link_mtu (int index,struct netif *nip,void * buf,int *offset) {
	struct rtattr x;
	/*printf("netif_out_link_mtu\n");*/
	unsigned int mtu=nip->mtu;
	x.rta_len=sizeof(struct rtattr)+sizeof(int);
	x.rta_type=index;
	netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
	netlink_addanswer(buf,offset,&mtu,sizeof(int));
}

static void netif_out_link_link (int index,struct netif *nip,void * buf,int *offset) {
}

typedef void (*opt_out_link)(int index,struct netif *nip,void * buf,int *offset);

static opt_out_link netif_link_out_table[]={
	NULL,
	netif_out_link_address,
	netif_out_link_broadcast,
	netif_out_link_ifname,
	netif_out_link_mtu,
	netif_out_link_link,
	NULL};
#define NETIF_LINK_OUT_SIZE (sizeof(netif_link_out_table)/sizeof(opt_out_link))


static void netif_netlink_link_out(struct nlmsghdr *msg,struct netif *nip,void * buf,int *offset)
{
	register int i;
	int myoffset=*offset;
	(*offset) += sizeof (struct nlmsghdr);

	struct ifinfomsg ifi;
	ifi.ifi_family=0; 
	ifi.__ifi_pad=0;
	ifi.ifi_type=nip->type; 
	ifi.ifi_index=nip->id;
	ifi.ifi_flags=nip->flags; 
	ifi.ifi_change=0xffffffff;
	netlink_addanswer(buf,offset,&ifi,sizeof (struct ifinfomsg));

	for (i=0; i< NETIF_LINK_OUT_SIZE;i++)
		if (netif_link_out_table[i] != NULL)
			netif_link_out_table[i](i,nip,buf,offset);
	msg->nlmsg_flags = NLM_F_MULTI;
	msg->nlmsg_type = RTM_NEWLINK;
	msg->nlmsg_len = *offset - myoffset;
	netlink_addanswer(buf,&myoffset,msg,sizeof (struct nlmsghdr));
}

void netif_netlink_getlink(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct ifinfomsg *ifi=(struct ifinfomsg *)(msg+1);
	struct netif *nip;
	int lenrestore=msg->nlmsg_len;
	int flag=msg->nlmsg_flags;
	/*printf("netif_netlink_getlink\n");*/
	if (msg->nlmsg_len < sizeof (struct nlmsghdr)) {
		fprintf(stderr,"Netlink getlink error\n");
		netlink_ackerror(msg,-ENXIO,buf,offset);
		return;
	}
	for (nip=netif_list; nip!=NULL; nip=nip->next)
	{
		if ((flag & NLM_F_DUMP) == NLM_F_DUMP ||
				ifi->ifi_index == nip->id)
			 netif_netlink_link_out(msg,nip,buf,offset);
	}
	msg->nlmsg_type = NLMSG_DONE;
	msg->nlmsg_flags = 0;
	msg->nlmsg_len = sizeof (struct nlmsghdr);
	netlink_addanswer(buf,offset,msg,sizeof (struct nlmsghdr));
	msg->nlmsg_len=lenrestore;
}

static void netif_out_addr_address(int index,struct netif *nip,struct ip_addr_list *ipl,void * buf,int *offset)
{
	struct rtattr x;
	int isv4=ip_addr_is_v4comp(&(ipl->ipaddr));
	x.rta_len=sizeof(struct rtattr)+((isv4)?sizeof(u32_t):sizeof(struct ip_addr));
	x.rta_type=index;
	netlink_addanswer(buf,offset,&x,sizeof (struct rtattr));
	if (isv4)
		netlink_addanswer(buf,offset,&(ipl->ipaddr.addr[3]),sizeof(u32_t));
	else
		netlink_addanswer(buf,offset,&(ipl->ipaddr),sizeof(struct ip_addr));
}

typedef void (*opt_out_addr)(int index,struct netif *nip,struct ip_addr_list *ipl,void * buf,int *offset);

static opt_out_addr netif_addr_out_table[]={
	NULL,
	netif_out_addr_address,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL};
#define NETIF_ADDR_OUT_SIZE (sizeof(netif_addr_out_table)/sizeof(opt_out_addr))


static void netif_netlink_out_addr(struct nlmsghdr *msg,struct netif *nip,struct ip_addr_list *ipl,void * buf,int *offset)
{
	register int i;
	int myoffset=*offset;
	(*offset) += sizeof (struct nlmsghdr);

	struct ifaddrmsg ifa;
	/*printf("netif_netlink_out_addr\n");*/
	ifa.ifa_family= ip_addr_is_v4comp(&(ipl->ipaddr))?PF_INET:PF_INET6; 
	ifa.ifa_prefixlen=mask2prefix(&(ipl->netmask))-(ip_addr_is_v4comp(&(ipl->ipaddr))?(32*3):0); 
	ifa.ifa_index=nip->id;
	ifa.ifa_flags=ipl->flags; 
	ifa.ifa_scope=0; 
	if ((ntohl(ipl->ipaddr.addr[0]) & 0xff000000) == 0xfe000000) {
		if ((ntohl(ipl->ipaddr.addr[0]) & 0xC00000) == 0x800000)
			ifa.ifa_scope=RT_SCOPE_LINK;
		else if ((ntohl(ipl->ipaddr.addr[0]) & 0xC00000)== 0x08000000)
			ifa.ifa_scope=RT_SCOPE_SITE;
	} else if ((ntohl(ipl->ipaddr.addr[0]) & 0xff000000) == 0) {
		if (ip_addr_is_v4comp(&(ipl->ipaddr))) {
			if (ntohl(ipl->ipaddr.addr[3]) >> 24 == 0x7f)
				ifa.ifa_scope=RT_SCOPE_HOST;
		} else
			ifa.ifa_scope=RT_SCOPE_HOST;
	}

	netlink_addanswer(buf,offset,&ifa,sizeof (struct ifaddrmsg));

	for (i=0; i< NETIF_LINK_OUT_SIZE;i++)
		if (netif_addr_out_table[i] != NULL)
			netif_addr_out_table[i](i,nip,ipl,buf,offset);
	msg->nlmsg_flags = NLM_F_MULTI;
	msg->nlmsg_type = RTM_NEWADDR;
	msg->nlmsg_len = *offset - myoffset;
	netlink_addanswer(buf,&myoffset,msg,sizeof (struct nlmsghdr));
}

void netif_netlink_getaddr(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
	/*char *opt=(char *)(ifa+1);*/
	struct netif *nip;
	int lenrestore=msg->nlmsg_len;
	int flag=msg->nlmsg_flags;
	/*printf("netif_netlink_getaddr\n");*/
	if (msg->nlmsg_len < sizeof (struct nlmsghdr)) {
		fprintf(stderr,"Netlink getlink error\n");
		netlink_ackerror(msg,-1,buf,offset);
		return;
	}
	for (nip=netif_list; nip!=NULL; nip=nip->next)
	{
		if ((flag & NLM_F_DUMP) == NLM_F_DUMP ||
				ifa->ifa_index == nip->id) {
			struct ip_addr_list *ial=nip->addrs;
			/*for(ial=nip->addrs;ial != NULL;ial=ial->next)*/
			if (ial != NULL) {
				ial=nip->addrs->next;
				do {
					netif_netlink_out_addr(msg,nip,ial,buf,offset);
					ial=ial->next;
				} while (ial != nip->addrs->next);
			}

		}
	}
	msg->nlmsg_type = NLMSG_DONE;
	msg->nlmsg_flags = 0;
	msg->nlmsg_len = sizeof (struct nlmsghdr);
	netlink_addanswer(buf,offset,msg,sizeof (struct nlmsghdr));
	msg->nlmsg_len=lenrestore;
}

void netif_netlink_adddeladdr(struct nlmsghdr *msg,void * buf,int *offset)
{
	struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
	struct rtattr *opt=(struct rtattr *)(ifa+1);
	struct netif *nip;
	int size=msg->nlmsg_len - sizeof(struct ifaddrmsg) - sizeof(struct nlmsghdr);
	struct ip_addr ipaddr,netmask;
	int err;

	/*printf("netif_netlink_adddeladdr %d\n",ifa->ifa_prefixlen);*/
	if (msg->nlmsg_len < sizeof (struct nlmsghdr)) {
		fprintf(stderr,"Netlink add/deladdr error\n");
		netlink_ackerror(msg,-ENXIO,buf,offset);
		return;
	}
	nip=netif_find_id(ifa->ifa_index);
	if (nip == NULL) {
		fprintf(stderr,"Netlink add/deladdr id error\n");
		netlink_ackerror(msg,-ENODEV,buf,offset);
		return;
	}

	memcpy(&ipaddr,IP_ADDR_ANY,sizeof(struct ip_addr));
	prefix2mask((int)(ifa->ifa_prefixlen)+(ifa->ifa_family == PF_INET?(32*3):0),&netmask);
	while (RTA_OK(opt,size)) {
		switch(opt->rta_type) {
			case IFA_ADDRESS:
			case IFA_LOCAL:
				if (ifa->ifa_family == PF_INET && opt->rta_len == 8) {
					ipaddr.addr[2]=IP64_PREFIX;
					ipaddr.addr[3]=(*((int *)(opt+1)));
				}
				else if (ifa->ifa_family == PF_INET6 && opt->rta_len == 20) {
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
				printf("Netlink: Unsupported IFA opt %d\n",opt->rta_type);
				break;
		}
		opt=RTA_NEXT(opt,size);
	}

	if (msg->nlmsg_type == RTM_NEWADDR) {
		err=netif_add_addr(nip,&ipaddr,&netmask);
	} else {
		err=netif_del_addr(nip,&ipaddr,NULL);
	}
	netlink_ackerror(msg,err,buf,offset);	
}

#endif
