/*   
 *   hashaddr.c: Virtual Web appliance
 *   
 *   Copyright 2011 Renzo Davoli - Virtual Square Team 
 *   University of Bologna - Italy
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
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <lwipv6.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <mhash.h>
#include <netdb.h>

void nowaddr(struct ip_addr *addr, char *fqn)
{
	char *s;
	MHASH td;
	unsigned char out[mhash_get_block_size(MHASH_MD5)];
	time_t now;
	int len=asprintf(&s,"%s",fqn);
	td=mhash_init(MHASH_MD5);
	mhash(td, s, len);
	mhash_deinit(td, out);
	free(s);

	addr->addr[2] ^= htonl(
		((out[0] ^ out[8]) << 24) |
		((out[1] ^ out[9]) << 16) |
		((out[2] ^ out[10]) << 8) |
		(out[3] ^ out[11]));
	addr->addr[3] ^= htonl(
		((out[4] ^ out[12]) << 24) |
		((out[5] ^ out[13]) << 16) |
		((out[6] ^ out[14]) << 8) |
		(out[7] ^ out[15]));
	printf("%x:%x:%x:%x:%x:%x:%x:%x\n",
			ntohl(addr->addr[0]) >> 16, ntohl(addr->addr[0]) & 0xffff,
			ntohl(addr->addr[1]) >> 16, ntohl(addr->addr[1]) & 0xffff,
			ntohl(addr->addr[2]) >> 16, ntohl(addr->addr[2]) & 0xffff,
			ntohl(addr->addr[3]) >> 16, ntohl(addr->addr[3]) & 0xffff);
}

int main(int argc, char *argv[])
{
	struct ip_addr addr;
	int ip1,ip2,ip3,ip4;
	char *pwd=argv[2];
	struct addrinfo *res;
	static struct addrinfo hints={.ai_family=AF_INET6};
	int gaierr;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s IPv6_64bits_prefix fqn\n"
		 "		e.g. %s 2001:2:3:: myweb.mynet.mydomain.org\n\n",
				argv[0],argv[0]);
		exit(1);
	}
	if ((gaierr=getaddrinfo(argv[1],NULL,&hints,&res))!=0) {
		fprintf(stderr,"prefix: %s\n",gai_strerror(gaierr));
		exit(1);
	}
	struct sockaddr_in6 *sock6=(struct sockaddr_in6 *)res->ai_addr;
	memcpy(&addr,&(sock6->sin6_addr),sizeof(addr));
	nowaddr(&addr,pwd);
}
