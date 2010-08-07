#ifndef _DNSFORWARD_H
#define _DNSFORWARD_H
#include <lwipv6.h>

int get_dns_addr(struct ip_addr *pdns_addr);
void dns_init(struct stack *stack, struct ip_addr *dnsaddr);

#endif
