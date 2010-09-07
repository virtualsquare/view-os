/*   This is part of uNAT
 *   Developed for the uNAT project
 *   Universal NAT
 *   
 *   Copyright 2004 Diego Billi - Italy
 *   Modified 2010 Renzo Davoli - Italy
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ctype.h>
#include <getopt.h>    // getopt() 

#include <sys/types.h>

#include "lwip/pbuf.h"
#include "lwip/nat/nat.h"
#include "lwip/nat/nat_rules.h"

#include "main.h"


#include "commands.h"

//============================================================================
// Globals
//============================================================================

static FILE *history = NULL;

static char command_bak[CMD_MAX_LEN+1];

// Needed for getopt() 
extern char *optarg;
extern int   optind, opterr, optopt;


//============================================================================
// Costants
//============================================================================

char *GETTOK(int argc, char *argv[], int pos)
{
	if (pos >= 0 && pos < argc)
		return argv[pos];
	else
		return NULL;
}

int tokenize(char *str, char **tokens, int max, int (*fun)(int c))
{
	char inside_token;
	int ntok;

	if (str == NULL || max == 0 || tokens == NULL || fun == NULL)
		return 0;

	inside_token = 0;
	ntok = 0;
	while (*str) {
		if (fun(*str)) {
			* str = '\0';	
			if (inside_token) {
				inside_token = 0;
				tokens[ntok+1] = NULL;
				if (ntok == max)  // add NULL token to the end
					break;
			}
		}
		else 
			// new token
			if (! inside_token) {
				tokens[ntok] = str;
				inside_token = 1;
				ntok++;
			}
		str++;
	}
	tokens[ntok+1] = NULL;

	return ntok;	
}


int is_empty_line(char *str)
{
	if (str == NULL)
		return 1;

	while (*str)
		if (isspace(*str))
			str++;
		else
			return 0;

	return 1;
}

//============================================================================


int commands_init(void)
{
	int r=1;

	history = tmpfile();
	if (history == NULL) {
		return 0;
	}

	return r;
}


//============================================================================
// Shell history functions
//============================================================================

void history_save(char *line)     
{
	if (history != NULL) { 
		if (fseek(history, 0, SEEK_END) < 0) {
			error_printf("*** unable to access to the history.\n");
    		return;
		}
		fputs(line, history); 
	} 
}

void history_print(void)
{
	char line[CMD_MAX_LEN];
	int i;

	if (history != NULL) 
	{
		if (fseek(history, 0, SEEK_SET) < 0) {
			error_printf("*** unable to access to the history.\n");
    		return;
		}

		i=0;
		while (fgets(line, CMD_MAX_LEN, history) != NULL) {
			printf("%3d  %s", i, line);
			i++;
		}
	}
}

void history_dump(char *filename)
{
	FILE *out;
	char line[CMD_MAX_LEN];
	int i;

	if (history != NULL)  {
		out = fopen(filename,"w+");
		if (out == NULL) {
			error_printf("*** unable to write '%s'!\n", filename);
			return;
		}
		verbose_printf("dumping history on '%s'...\n", filename);

		if (fseek(history, 0, SEEK_SET) < 0) {
			error_printf("*** unable to access to the history.\n");
			return;
		}

		i=0;
		while (fgets(line, CMD_MAX_LEN, history) != NULL) {
			fputs(line, out);
			i++;
		}
		fclose(out);

		verbose_printf("dump finished!\n");
	}
}

void history_redo(int pos)
{
	char line[CMD_MAX_LEN];
	int i;

	if (history != NULL)  {
		if (fseek(history, 0, SEEK_SET) < 0) {
			error_printf("*** unable to access to the history.\n");
	    		return;
		}
	
		i=0;
		while (fgets(line, CMD_MAX_LEN, history) != NULL) {
			if (pos == i) {
				parse_command_line(line);
				return;
			}
			i++;
		}
		error_printf("*** event not found!\n");
	}
}

//============================================================================

void show_help(void)
{
	printf("Commands:\n");
	printf("help \n");
	printf("verbose ( on | off ) \n");
	printf("exit \n");
	printf("system <cmd> <arg1> <arg2> ecc....\n");
	printf("\n");
	printf("history \n");
	printf("history dump <filename> \n");
	printf("! <n> \n");
	printf("\n");
	printf("drivers \n");
	printf("\n");
	printf("iface list \n");
	printf("iface add <interface> [driver] <driver_name> [[param] <driver_param>] \n");
	printf("iface up <interface> \n");
	printf("iface down <interface> \n");
	printf("\n");
	printf("ip (add|del) <interface> [ip] <ip> [netmask] <netmask> \n");
	printf("\n");
	printf("route list\n");
	printf("route (add|del) [ip] <ip> [netmask] <netmask> [nexthop] <ip_nexthop> [dev] <interface>  \n");
	printf("route delif <interface> \n");
#ifdef LWIP_NAT
	printf("\n");
	printf("nat list \n");
	printf("nat -L \n");
	printf("nat -D <table> <rulenum> \n");
	printf("nat (-A|--append) <table> [options]  (-j|--jump) <target>\n");
	printf("\n");
	printf("Options:\n");
	printf("  -i | --in-interface <interface>\n");
	printf("  -o | --out-interface <interface>\n");
	printf("  -p | --protocol <protocol_name>\n");
	printf("  -s | --source <ip>\n");
	printf("  -d | --destination <ip>\n");
	printf("  --sport | --source-port <port>\n");
	printf("  --dport | --destination-port <port>\n");
	printf("Target:\n");
	printf("  MASQUARADE\n");
	printf("  DNAT --to-source|--src <ip4>[:<port>]\n");
	printf("  SNAT --to-destination|--dest <ip4>[:<port>]\n");
#endif
}                                   


//============================================================================

#define CMD_HELP_STR     "help"
#define CMD_EXIT_STR     "exit"
#define CMD_SYSTEM_STR   "system"
#define CMD_HISTORY_STR  "history"
#define CMD_REDO_STR     "!"
#define CMD_VERBOSE_STR  "verbose"
#define CMD_DRIVERS_STR  "drivers"
#define CMD_IFACE_STR    "iface"
#define CMD_IP_STR       "ip"
#define CMD_ROUTE_STR    "route"
#define CMD_NAT_STR      "nat"


//============================================================================
// NAT command parsing functions
//============================================================================
#ifdef LWIP_NAT

static int is_ip4portsep(int c)
{
	if (c == ':') return 1;
	else return 0;
}

//
// Parses 'nat' command and call app_nat_add() function.
//
//HELP nat (-A|--append) <table> [options]  (-j|--jump) <target>
//
//HELP Options:
//HELP -i  | --in-interface <interface>
//HELP -o  | --out-interface <interface>
//HELP -ip | --ip-version (4|6)
//HELP -s  | --source <ip>
//HELP -d  | --destination <ip>
//HELP -p  | --protocol (tcp|udp)
//HELP --sport | --source-port <port>
//HELP --dport | --destination-port <port>
//	
//HEMP  Targets:
//HELP 	MASQUARADE
//HELP 	DNAT  (--to-source|--src) <ip> [<port>]
//HELP 	SNAT  (--to-destination|--dest) <ip> [<port>-<port>]
//	

#define  is_option(str, opt, alt)  (strcmp((str),(opt)) == 0  || ( (alt) ? strcmp((str),(alt)) == 0 : 0 ))


static int is_portsep(int c)
{
	if (c == '-') return 1;
	else return 0;
}

static int parse_target(char **ipmin, char **ipmax, char **portmin, char **portmax, char *argv[], int argc, int *pos, char *jump)
{
	char *option;

	char *ip_str =  NULL;
	char *ports =  NULL;

	printf("1\n");

	if (strcmp(jump, "MASQUERADE")  == 0) { 
        	return 1;
	}

	*pos += 2;

	if ((*pos) < argc) {
		// If option is followed by a string value 
		option  = argv[*pos];
		ip_str  = GETTOK(argc, argv, (*pos)+1);
		ports   = GETTOK(argc, argv, (*pos)+2);

		error_printf("'%s' '%s' '%s'\n", option, ip_str, ports);

		*pos += 2;
	}
	else {
		error_printf("*** missing parameter!\n");
	}

	if (strcmp(jump, "DNAT")  == 0) { 

		printf("2\n");

		if (is_option(option, "--to-destination", "--dest")) {

			printf("3\n");

			if (ip_str == NULL) {
				error_printf("*** missing IP parameter!\n");
				return -1;
			}

			* ipmin = ip_str;

			if (ports != NULL) {
				* portmin = ports;
			}

			return 1;
		}
		else {
			error_printf("*** wrong parameter '%s'!\n", option);
		}
	}

	if (strcmp(jump, "SNAT")  == 0) {

		printf("s2\n");

		if (is_option(option, "--to-source", "--src")) {


			printf("s3\n");

			if (ip_str == NULL) {
				error_printf("*** missing IP parameter!\n");
				return -1;
			}

			* ipmin = ip_str;

			printf("%s\n", *ipmin);

			if (ports != NULL) {
                  		char *port_vet[3];
				int n;
	
				if ((n = tokenize(ports, port_vet, 2, is_portsep)) >= 1) {
				
					* portmin = GETTOK(n, port_vet, 0);
					* portmax = GETTOK(n, port_vet, 1);

					printf("%s %s %d\n", *portmin, *portmax, n);

					if ((*portmin == NULL)  ||
					    (*portmax == NULL && n > 1)) {
						error_printf("*** invalid port range '%s'!\n", ports);
					}

				}
				else {
					error_printf("*** invalid port range '%s'!\n", ports);
					return -1; 
				}
			}

			return 1;
		}
		else {
			error_printf("*** wrong parameter '%s'!\n", option);
		}
	}

	return -1;
}


static int parse_nat(int argc, char *argv[])
{
	int pos;
	char *option;
	char *value;
	
	char *where = NULL;
	int  ipv   = 0;
	char *proto = NULL;
	char *sip   = NULL;
	char *dip   = NULL;
	char *dport = NULL;
	char *sport = NULL;
	char *in    = NULL;
	char *out   = NULL;

	char *jump  = NULL;
	
	char *joption = NULL;
	char *joption_param = NULL;
		char *target_ip_min = NULL;
		char *target_ip_max = NULL;
		char *target_port_min = NULL;
		char *target_port_max = NULL;
		
	int error = 0;

	pos = 1;
	while (pos < argc)
	{
		// If option is followed by a string value 
		option = argv[pos];
		value = GETTOK(argc, argv, pos+1);
		
		if (is_option(option, "-A","--append")) {
			where = value; 
			if (pos != 1) { // This options must be the first
				error_printf("*** option '%s' must be first!\n", argv[pos]);
				error = 1;
				break;
			}	
		}
		else if (is_option(option, "-ip"    , "--ip-version")) {
			if (ipv) {
				error_printf("*** IP version already defined\n");
				error = 1;
				break;
			}
			else {
				if (strcmp(value, "4")==0) ipv = 4;
				else if (strcmp(value, "6")==0) ipv = 6;
				else {
					error_printf("*** wrong ipv\n");
					error = 1;
					break;
				}
			}
		}
		else if (is_option(option, "-i",  "--in-interface" )) {
			if (! out) in  = value;
			else {
				error_printf("*** also output interface is defined\n");
				error = 1;
				break;
			}
		}
		else if (is_option(option, "-o" , "--out-interface" )) {
			if (! in) out = value;
			else {
				error_printf("*** also input interface is defined\n");
				error = 1;
				break;
			}
		}
		else if (is_option(option, "-p"     , "--protocol"        )) proto= value;
		else if (is_option(option, "-s"     , "--source"          )) sip = value;
		else if (is_option(option, "-d"     , "--destination"     )) dip = value;
		else if (is_option(option, "--sport", "--source-port"     )) sport = value;
		else if (is_option(option, "--dport", "--destination-port")) dport = value;
		else if (is_option(option, "-j"     , "--jump"            )) { 
			jump = value;	

			if (jump == NULL) {
				error_printf("*** missing NAT target\n");
				error = 1;
				break;
			}

			if ((strcmp(jump, "MASQUERADE") != 0) &&
			    (strcmp(jump, "DNAT")  != 0) && 
			    (strcmp(jump, "SNAT")  != 0)) {
					error_printf("*** unknown NAT target '%s'.\n", jump);
					error = 1;
				break;
			}

			if (parse_target(&target_ip_min, &target_ip_max, &target_port_min,  &target_port_max, 
				argv, argc, &pos, jump) < 0) {
                                error = 1;
			}
			break;                      
		}
		else {
			error_printf("*** unknown option '%s'.\n", option);
			error = 1;
			break;
		}

		if (value == NULL) {
			error_printf("*** missing value for option '%s'\n", argv[pos]);
			error = 1;
			break;
		}

		pos+=2; // jump to the next --option <value>
	}
	
	if (error == 0 && pos < argc -2) 
		error_printf("*** ATTENTION: to many options for NAT target. They will be ignored!\n");

	if (!error) {
	
		nat_table_t  nat_table;
		nat_type_t     nat_type;
		char *ifname;

		if (!ipv) ipv = 4;
		
		// check NAT table
		if (strcmp(where, "PREROUTING") == 0)       nat_table = NAT_PREROUTING;
		else if (strcmp(where, "POSTROUTING") == 0) nat_table = NAT_POSTROUTING;
		else { error_printf("*** invalid value '%s'\n", where); return -1; }
		
		// check NAT target
		if (strcmp(jump, "SNAT") == 0)            nat_type = NAT_SNAT;
		else if (strcmp(jump, "DNAT" ) == 0)      nat_type = NAT_DNAT;
		else if (strcmp(jump, "MASQUERADE") == 0) nat_type = NAT_MASQUERADE;
		else return -1;
		
		// set rule
		if (nat_type == NAT_MASQUERADE || nat_type == NAT_SNAT) {
			ifname = out;
		}
		else
			ifname = in;
		
		app_nat_add (ipv, nat_table, nat_type, ifname, proto, sip, dip, dport, sport, target_ip_min, NULL, target_port_min, NULL);
		
		return 1;
	}
	
	return -1;
}

#endif

//============================================================================

#define MAX_TOKENS 256
static char *tokens[MAX_TOKENS+1];

#define create_tokens(str) (tokenize((str), tokens, MAX_TOKENS, isspace))
#define get_token(pos)  GETTOK(MAX_TOKENS, tokens, pos)


int parse_command_line(char* line) 
{
	char *cmd;
	int num;
	int r;

	int save_history = 1;

	if (is_empty_line(line)) return 1;

	if (line[0] == '#')      return 1;

	// save command line before create tokens
	bzero(command_bak, CMD_MAX_LEN+1);
	strcpy(command_bak, line);
	
	num = create_tokens(line);
	if (num == 0) {
		error_printf("*** unable to parse command line.\n");
		return 1;
	}

	cmd = get_token(0);

	do {
		
	r = 1;

	//
	//HELP help 
	//
	if ((r = strcmp(cmd, CMD_HELP_STR)) == 0) { 
		show_help(); 
		break; 
	}
	//
	//HELP exit
	//
	if ((r = strcmp(cmd, CMD_EXIT_STR)) == 0) { 
		app_quit(); 
		break; 
	}
	//
	//HELP system <cmd> <arg1> <arg2> ecc....
	//
	if ((r = strcmp(cmd, CMD_SYSTEM_STR)) == 0) { 
    	if (num > 1)
			app_syscmd2(&tokens[1]);
		else
			error_printf("*** missing arguments\n");
		break; 
	}
	//
	//HELP history
	//HELP history dump <filename>
	//
	if ((r = strcmp(cmd, CMD_HISTORY_STR)) == 0) {

		if (num == 1) 
			history_print();    		
		else
		if ((num > 1) && (num == 3)) {
			if (strcmp(get_token(1), "dump") == 0) {
				history_dump(get_token(2));
			}
			else
				error_printf("*** invalid argument '%s'\n", get_token(1));
		}
		else
			error_printf("*** wrong or missing argument\n");
		break;
	}
	//
	//HELP ! <n>
	//
	if ((r = strcmp(cmd, CMD_REDO_STR)) == 0) {

		save_history = 0;

		if (num == 2) {
			int n;
			n = strtol(get_token(1), (char **)NULL, 10);
			if ((errno != ERANGE) && (n >= 0)) {
				history_redo(n);
			} else
				error_printf("*** invalid value '%s'!\n", get_token(1));
		} 
		else
			error_printf("*** missing argument\n");
		break;
	}
	//
	//HELP verbose ( on | off )
	//
	if ((r = strcmp(cmd, CMD_VERBOSE_STR)) == 0) {

		if (num == 2) {
			if (strcmp(get_token(1), "on") == 0)  app_set_verbose(1);
			else 
			if (strcmp(get_token(1), "off") == 0) app_set_verbose(0);
			else
				error_printf("*** invalid parameter '%s'.", get_token(1));
		} 
		else
			error_printf("*** missing argument\n");
		break;
	}

	//
	//HELP drivers
	//
	if ((r = strcmp(cmd, CMD_DRIVERS_STR)) == 0) { 
		app_drivers_list();
		break; 
	}

	//
	//HELP iface list
	//HELP iface add <interface> [driver] <driver_name> [[param] <driver_param>]
	//HELP iface up <interface>
	//HELP iface down <interface>
	//
	if ((r = strcmp(cmd, CMD_IFACE_STR)) == 0) { 
		if (num == 2 && strcmp(get_token(1), "list") == 0) 
			app_iface_list();
		else
		if (num == 3 && strcmp(get_token(1), "up") == 0) 
			app_iface_updown(1, get_token(2));
		else
		if (num == 3 && strcmp(get_token(1), "down") == 0) 
			app_iface_updown(0, get_token(2));
		else
		if (num == 3 && strcmp(get_token(1), "del") == 0) 
			app_iface_remove(get_token(2));
		else
		if ((num >= 4) && strcmp(get_token(1), "add") == 0) {
			char *name = get_token(2);
			char *driver = NULL;
			char *param = NULL;
			int pos;
			
			pos = 3;
			driver = get_token(pos);
			if (driver != NULL && strcmp(driver, "driver") == 0)
				driver = get_token(++pos);

			if (driver == NULL) {
				error_printf("*** missing driver name\n");
				break;
			}
			
			param = get_token(++pos);
			if (param != NULL) {
				if (strcmp(param, "param") == 0)
					param = get_token(++pos);
				if (param == NULL) {
					error_printf("*** missing parameter value!\n");
					break;
				}
			}
			app_iface_create(name, driver, param);
		} else
			error_printf("*** invalid or missing argument\n");
		break;
	}
	//
	//HELP ip (add|del) <interface> [ip] <ip> [netmask] <netmask> )
	//
	if ((r = strcmp(cmd, CMD_IP_STR)) == 0) { //   ||  (v6 = strcmp(cmd, CMD_IP6_STR)) == 0) { 
		if (num >= 5) {
			int pos;
			int action;
			char *name = NULL;
			char *ip = NULL;
			char *net = NULL;
			
			if (strcmp(get_token(1), "add") == 0) action = 1;
			else if (strcmp(get_token(1), "del") == 0) action = 0;
			else {
				error_printf("*** invalid parameter '%s'.", get_token(1));
				break;
			}
			
			name = get_token(2);
			
			pos = 2;
			ip = get_token(++pos);
			if (ip != NULL && strcmp(ip, "ip") == 0)
				ip = get_token(++pos);
			if (ip == NULL) {
				error_printf("*** missing IP value\n");
				break;
			}
			
			if (++pos > 3) {
				net = get_token(pos);
				if (net != NULL && strcmp(net, "netmask") == 0)
					net = get_token(++pos);
			}
			if (net == NULL) {
				error_printf("*** missing netmask value\n");
				break;
			}
				
			app_ip_adddel(action, name, ip, net);
		}
		else
			error_printf("*** invalid or missing argument\n");
		break;
	}
	//
	//HELP route list
	//HELP route (add|del) [ip] <ip> [netmask] <netmask> [nexthop] <ip_nexthop> [dev] <interface> 
	//HELP route delif <interface>
	//
	if ((r = strcmp(cmd, CMD_ROUTE_STR)) == 0) { 
		printf("num %d\n", num);
		if (num == 2 && strcmp(get_token(1), "list") == 0)
			app_route_list();
		else
		if (num == 3 && strcmp(get_token(1), "delif") == 0)
			app_route_delif(get_token(2));
		else
		if (num >= 6) {
			int pos;
			int action = 0;
			char *ip = NULL;
			char *net = NULL;
			char *next = NULL;
			char *dev = NULL;
			pos = 1;
			if (strcmp(get_token(pos), "add") == 0) action = 1;
			else if (strcmp(get_token(pos), "del") == 0) action = 0;
			pos++;
			
			ip = get_token(pos);
			if (ip != NULL && strcmp(ip, "ip") == 0)
				ip = get_token(++pos);
			if (ip == NULL) {
				error_printf("*** missing IP value\n");
				break;
			}	
			
			if (++pos > 2) {
				net = get_token(pos);
				if (net != NULL && strcmp(net, "netmask") == 0)
					net = get_token(++pos);
			}
			if (net == NULL) {
				error_printf("*** missing netmask value\n");
				break;
			}
			
			if (++pos > 3) {
				next = get_token(pos);
				if (next != NULL && strcmp(next, "nexthop") == 0)
					next = get_token(++pos);
			}
			if (next == NULL) {
				error_printf("*** missing next hop value\n");
				break;
			}	

			if (++pos > 4) {
				dev = get_token(pos);
				if (dev != NULL && strcmp(dev, "dev") == 0)
					dev = get_token(++pos);
			}
			if (dev == NULL) {
				error_printf("*** missing device name\n");
				break;
			}		

			app_route_adddel(action, ip, net, next, dev); 
		}
		else
			error_printf("*** invalid or missing argument\n");
		break; 
	}

#ifdef LWIP_NAT
	//
	//HELP nat -A ....
	//HELP nat -L
	//HELP nat -D <table> <rule pos>
	//
	if ((r = strcmp(cmd, CMD_NAT_STR)) == 0) {
		//if (num == 2 && strcmp(get_token(1), "stat") == 0)
		//	app_nat_stat(4);
		//else
		if (num == 2 && strcmp(get_token(1), "-L") == 0)
			app_nat_list(4);
		else
		if (num > 2 && (strcmp(get_token(1), "-A") == 0 || 
				strcmp(get_token(1), "--append") == 0))
			parse_nat(num, tokens);
		else 
		if (num == 4 && strcmp(get_token(1), "-D") == 0) {
			char *tablename = get_token(2);
			char *rule = get_token(3);
			nat_table_t table;
			int n;
			
			if (strcmp(tablename, "PREROUTING") == 0) table = NAT_PREROUTING; 
			else if (strcmp(tablename, "POSTROUTING") == 0) table = NAT_POSTROUTING;
			else {
				error_printf("*** invalid table '%s'!\n", tablename);		
				break;
			}
			
			n = strtol(rule, (char **)NULL, 10);
			if ((errno != ERANGE) && (n >= 0)) {
				app_nat_del(4, table, n);
			} else
				error_printf("*** invalid value '%s'!\n", rule);			
		}
		else
			error_printf("*** invalid or missing argument\n");			

		break; 
	}

#endif

	//
	// end
	//
	} while(0);

	if (save_history)
		history_save(command_bak);

	if (r)
		error_printf("*** command not found\n");

	return !r;
}



		// check nat options
/*		if (nat_type != NAT_MASQUERADE && ! joption_param) {
			error_printf("*** missing options for this type of NAT rule!\n");
			return -1;
		}

		if (nat_table == NAT_POSTROUTING) {
			if ((nat_type != NAT_SNAT) && (nat_type != NAT_MASQUERADE))  {
				error_printf("*** invalid NAT type with output interface!\n");
				return -1;
			}
		}
		else {
			if (nat_type != NAT_DNAT) {
				error_printf("*** invalid NAT type with input interface!\n");
				return -1;
			}
		}
*/

		/*
		if (nat_type == NAT_MASQUERADE) {
			target_ip_min = NULL;
			target_port_min = NULL;
		}
		else 
		{
			char *str_ip_port[3];
			int n;

			if ((n = tokenize(joption_param, str_ip_port, 2, is_ip4portsep)) >= 1) {
				
				printf("jip '%s'\n", GETTOK(n, str_ip_port, 0));
				printf("jport '%s'\n", GETTOK(n, str_ip_port, 1));
				
				target_ip_min = GETTOK(n, str_ip_port, 0); //str_ip_port[0];
				target_port_min = GETTOK(n, str_ip_port, 1); //str_ip_port[1];
			}
			else {
				error_printf("*** invalid ip:port value!\n");
				return -1; 
			}
		}
		*/		


/*		else if (is_option(option, "--to-destination", "--dest")) {
			if (strcmp(jump, "DNAT")  == 0) { 
				joption_param = value;
			} else {
				error = 1;
				break;
			}
		}
		else if (is_option(option, "--to-source", "--src")) {
			if (strcmp(jump, "SNAT")  == 0) {
				joption_param = value;
			} else {
				error = 1;
				break;
			}
		}
*/
