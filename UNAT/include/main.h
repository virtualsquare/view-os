/*   This is part of uNAT
 *   Developed for the uNAT project
 *   Universal NAT
 *   
 *   Copyright 2004 Diego Billi - Italy
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
#ifndef __UNAT_MAIN_H_
#define __UNAT_MAIN_H_


#define SHELL_PROMPT  "unat> "

#define CMD_MAX_LEN 256

void error_printf(const char *format, ...);

void verbose_printf(const char *format, ...);

void app_quit(void);
void app_set_verbose(int mode);

void app_syscmd(char *sysline);
void app_syscmd2(char **argv);

void app_drivers_list(void);

void app_iface_list(void);
void app_iface_create(char *name, char *driver, char *param);
void app_iface_remove(char *name);
void app_iface_updown(int up, char *name);

void app_ip_adddel(int cmd, char *ifname, char *ip, char *net);

void app_route_list(void);
void app_route_adddel(int cmd, char *ip4, char *net, char *nexthop, char *ifname );
void app_route_delif(char *ifname);

#ifdef LWIP_NAT

void app_nat_stat(int ipv);
void app_nat_list(int ipv);
void app_nat_del(int ipv, nat_table_t pos, int num);

void app_nat_add(int ipv, 
	nat_table_t pos, 
	nat_type_t type, 
	char *ifname,
	char *proto,
	char *sip, char *dip,
	char *dport, char *sport,
	//char *in_if,
	//char *out_if,
	char *ip_min, char *ip_max,
	char *port_min, char *port_max);
#endif	
	

#endif

