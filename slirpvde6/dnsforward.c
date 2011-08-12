/*
 * dnsforward.c - a simple, dnsforward
 * Copyright 2010 Renzo Davoli
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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "dnsforward.h"
#include "slirpvde6.h"

#define O_BINARY 0

/*
void mdump(void *s, int len)
{
	int i;
	unsigned char *c=s;
	for (i=0;i<len;i++)
		printf("%02x ",c[i]);
	printf("\n");
}
*/
#define DNS_SESSIONS_MAX 3

struct dns_data {
	struct stack *stack;
	int fdin;
	struct sockaddr_in6 dnsaddr;
	int dynamic;
};

static struct dns_data dns_data;

struct dns_session {
		struct sockaddr *client_addr;
		int client_addr_len;
		int fdout;
		struct dns_data *dnsd;

    time_t timestamp;
};

static struct dns_session dns_sessions[DNS_SESSIONS_MAX];

static inline void dns_session_terminate(struct dns_session *dnx)
{
	if (dnx->client_addr) {
		free(dnx->client_addr);
		slirpoll_delfd(dnx->fdout);
		close(dnx->fdout);
		dnx->client_addr=NULL;
	}
}

static inline int dns_session_in_use(struct dns_session *dnx)
{
	if ((int)(time(NULL) - dnx->timestamp) > 5) 
		dns_session_terminate(dnx);
	return (dnx->client_addr != NULL);
}

static inline void dns_session_update(struct dns_session *dnx)
{
	dnx->timestamp = time(NULL);
}

static int dns_session_allocate(struct sockaddr *addr, int addrlen, 
		int fdout, struct dns_data *dnsd)
{
  struct dns_session *dnx;
  int k;
	unsigned int mintime = ~0;
	int kmin;

  for (k = 0; k < DNS_SESSIONS_MAX; k++) {
    dnx = &dns_sessions[k];

    if (!dns_session_in_use(dnx))
        goto found;

		if (dns_sessions[k].timestamp < mintime) {
			mintime=dns_sessions[k].timestamp;
			kmin=k;
		}
  }

#ifdef NOLRU
  return -1;
#else
	//LRU
	k=kmin;
	dnx=&dns_sessions[k];
	dns_session_terminate(dnx);
#endif

 found:
  memset(dnx, 0, sizeof(*dnx));
	dnx->client_addr=malloc(addrlen);
  memcpy(dnx->client_addr, addr, addrlen);
	dnx->client_addr_len=addrlen;
	dnx->dnsd=dnsd;
	dnx->fdout=fdout;

  dns_session_update(dnx);

  return k;
}

static int dns_session_find(struct sockaddr *addr, int addrlen)
{
  struct dns_session *dnx;
  int k;

  for (k = 0; k < DNS_SESSIONS_MAX; k++) {
    dnx = &dns_sessions[k];

    if (dns_session_in_use(dnx)) {
      if (dnx->client_addr_len == addrlen &&
					memcmp(dnx->client_addr, addr, addrlen)==0) 
				return k;
    }
  }
  return -1;
}

int get_dns_addr(struct ip_addr *pdns_addr)
{
	char buff[512];
	char buff2[257];
	FILE *f;
	int found = 0;
	struct ip_addr tmp_addr;
	static struct stat dns_addr_stat;
	static struct ip_addr dns_addr;
	time_t dns_addr_time;

	if (memcmp(&dns_addr, IP_ADDR_ANY, sizeof(struct ip_addr)) != 0) {
		struct stat old_stat;
		if ((time(NULL) - dns_addr_time) < 2) {
			*pdns_addr = dns_addr;
			return 0;
		}
		old_stat = dns_addr_stat;
		if (stat("/etc/resolv.conf", &dns_addr_stat) != 0)
			goto dnserr;
		if ((dns_addr_stat.st_dev == old_stat.st_dev)
				&& (dns_addr_stat.st_ino == old_stat.st_ino)
				&& (dns_addr_stat.st_size == old_stat.st_size)
				&& (dns_addr_stat.st_mtime == old_stat.st_mtime)) {
			*pdns_addr = dns_addr;
			return 0;
		}
	}

	f = fopen("/etc/resolv.conf", "r");
	if (!f)
		return -1;

#ifdef DEBUG
	printf("IP address of your DNS(s): ");
#endif
	while (fgets(buff, 512, f) != NULL) {
		if (sscanf(buff, "nameserver%*[ \t]%256s", buff2) == 1) {
			if (!lwip_inet_aton(buff2, &tmp_addr))
				continue;
			/* If it's the first one, set it to dns_addr */
			if (!found) {
				*pdns_addr = tmp_addr;
				dns_addr = tmp_addr;
				dns_addr_time = time(NULL);
			}
#ifdef DEBUG
			else
				printf(", ");
#endif
			if (++found > 3) {
#ifdef DEBUG
				printf("(more)");
#endif
				break;
			}
#ifdef DEBUG
			else {
				char hostbuf[NAMEINFO_LEN];
				printf("%s", lwip_inet_ntoa(&tmp_addr, hostbuf, NAMEINFO_LEN));
			}
#endif
		}
	}
#ifdef DEBUG
	printf("\n");
#endif
	fclose(f);
	if (found)
		return 0;
dnserr:
	memset(pdns_addr,0,sizeof(struct ip_addr));
	return -1;
}

static void dns_reply_input(int fd, void *arg)
{
	int s=(int) arg;
	char buf[1500];
	int len=recv(fd, buf, sizeof(buf),0);
	//printf("dns <- %d %d\n",s,len);
	lwip_sendto(dns_sessions[s].dnsd->fdin,buf,len,0,
			dns_sessions[s].client_addr,
			dns_sessions[s].client_addr_len);
}

static void dns_lwip_input(int fd, void *arg)
{
	char buf[1500];
	struct sockaddr_in6 src6;
	struct sockaddr *src_addr=(struct sockaddr *)&src6;
	int srclen=sizeof(src6);
	int len=lwip_recvfrom(fd, buf, sizeof(buf),0,src_addr,&srclen);
	struct dns_data *dnsd = arg;

	int s=dns_session_find(src_addr,srclen);
	if (s<0) {
		int outfd;
		struct sockaddr_in6 saddr;
		outfd=socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = 0;
		saddr.sin6_addr = in6addr_any;
		bind(outfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
		s=dns_session_allocate(src_addr,srclen,outfd,dnsd);
		if (s<0)
			close(outfd);
		else
			slirpoll_addfd(outfd,dns_reply_input,(void *) s);
	}
	//printf("dns -> %d %d\n",s,len);
	if (s>=0) {
		if (dns_data.dynamic) {
			get_dns_addr((struct ip_addr *)&dns_data.dnsaddr.sin6_addr);
			sendto(dns_sessions[s].fdout, buf, len, 0, 
					(struct sockaddr *)&dnsd->dnsaddr, sizeof(dnsd->dnsaddr));
		} else
			sendto(dns_sessions[s].fdout, buf, len, 0, 
					(struct sockaddr *)&dnsd->dnsaddr, sizeof(dnsd->dnsaddr));
	}
}

void dns_init(struct stack *stack, struct ip_addr *dnsaddr)
{
	struct sockaddr_in6 saddr;
	int dnsfd;
	dnsfd=lwip_msocket(stack, PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(53);
	saddr.sin6_addr = in6addr_any;
	lwip_bind(dnsfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6));
	dns_data.stack=stack;
	dns_data.dnsaddr.sin6_family=AF_INET6;
	dns_data.dnsaddr.sin6_port=htons(53);
	if (dnsaddr) {
		memcpy(&dns_data.dnsaddr.sin6_addr,dnsaddr,sizeof(struct ip_addr));
		dns_data.dynamic=0;
	} else
		dns_data.dynamic=1;
	dns_data.fdin=dnsfd;
	slirpoll_addfd(dnsfd,dns_lwip_input,&dns_data);
}
