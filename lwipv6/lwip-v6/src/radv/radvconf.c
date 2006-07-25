/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2005 Diego Billi University of Bologna - Italy
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

#include "lwip/opt.h"

#if IPv6_RADVCONF

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"

#include "lwip/icmp.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "lwip/ip_radv.h"
#include "lwip/radvconf.h"

#ifndef IP_RADVCONF_DEBUG
#define IP_RADVCONF_DEBUG DBG_ON
#endif                                              

#define ASCIILINESZ	1024

char * strlwc(char * s)
{
    static char l[ASCIILINESZ+1];
    int i ;

    if (s==NULL) return NULL ;
    memset(l, 0, ASCIILINESZ+1);
    i=0 ;
    while (s[i] && i<ASCIILINESZ) {
        l[i] = (char)tolower((int)s[i]);
        i++ ;
    }
    l[ASCIILINESZ]=(char)0;
    return l ;
}

char * strupc(char * s)
{
    static char l[ASCIILINESZ+1];
    int i ;

    if (s==NULL) return NULL ;
    memset(l, 0, ASCIILINESZ+1);
    i=0 ;
    while (s[i] && i<ASCIILINESZ) {
        l[i] = (char)toupper((int)s[i]);
        i++ ;
    }
    l[ASCIILINESZ]=(char)0;
    return l ;
}

char * strskp(char * s)
{
    char * skip = s;
	if (s==NULL) return NULL ;
    while (isspace((int)*skip) && *skip) skip++;
    return skip ;
} 

char * strcrop(char * s)
{
    static char l[ASCIILINESZ+1];
	char * last ;

    if (s==NULL) return NULL ;
    memset(l, 0, ASCIILINESZ+1);
	strcpy(l, s);
	last = l + strlen(l);
	while (last > l) {
		if (!isspace((int)*(last-1)))
			break ;
		last -- ;
	}
	*last = (char)0;
    return l ;
}

char * strstrip(char * s)
{
    static char l[ASCIILINESZ+1];
	char * last ;
	
    if (s==NULL) return NULL ;
    
	while (isspace((int)*s) && *s) s++;
	
	memset(l, 0, ASCIILINESZ+1);
	strcpy(l, s);
	last = l + strlen(l);
	while (last > l) {
		if (!isspace((int)*(last-1)))
			break ;
		last -- ;
	}
	*last = (char)0;

	return (char*)l ;
}

/*--------------------------------------------------------------------------*/

char * str_strip(char *str)
{
	char * last;

	if (str==NULL) return NULL ;
	
	while (isspace((int)*str) && *str) 
		str++;
	
	last = str + strlen(str);
	while (last > str) {
		if (!isspace((int)*(last-1)))
			break ;
		last -- ;
	}
	*last = (char)0;
	
	return (char*)str ;
}


int str_to_bool(u8_t *bool, char *str)
{
	if (strcmp(str, "true") == 0) { *bool=1; return 1; }
	if (strcmp(str, "TRUE") == 0) { *bool=1; return 1; }
	if (strcmp(str, "on") == 0) { *bool=1; return 1; }
	if (strcmp(str, "ON") == 0) { *bool=1; return 1; }
	if (strcmp(str, "false") == 0) { *bool=0; return 1; }
	if (strcmp(str, "FALSE") == 0) { *bool=0; return 1; }
	if (strcmp(str, "off") == 0) { *bool=0; return 1; }
	if (strcmp(str, "OFF") == 0) { *bool=0; return 1; }
	return 0;
}

int str_to_int(u32_t *val, char *str)
{
	unsigned int integer;
	char *ptr = NULL;
	integer = strtol(str, &ptr, 10);
	if (errno == ERANGE || *ptr != '\0') return 0;
	else {
		*val = integer;
		return 1;
	}
}

int str_to_int_or_infinity(u32_t *val, char *str)
{
	if (strcmp(str, "infinity") == 0 || strcmp(str, "INFINITY") == 0) {
		*val = 0xffffffff;
		return 1;
	} else
		return str_to_int(val, str);
}

int str_to_short(u16_t *val, char *str)
{
	unsigned int integer;
	char *ptr = NULL;
	integer = strtol(str, &ptr, 10);
	if (errno == ERANGE || *ptr != '\0') return 0;
	else {
		* val = (u16_t) integer;	
		return 1;
	}
}

int str_to_char(u8_t *val, char *str)
{
	unsigned int integer;
	char *ptr = NULL;
	integer = strtol(str, &ptr, 10);
	if (errno == ERANGE || *ptr != '\0') return 0;
	else {
		* val = (char) integer;	
		return 1;
	}
}

static char *GETTOK(int argc, char *argv[], int pos)
{
	if (pos >= 0 && pos < argc)
		return argv[pos];
	else
		return NULL;
}

static  int tokenize(char *str, char **tokens, int max, char sep)
{
	char inside_token;
	int ntok;

	if (str == NULL || max == 0 || tokens == NULL)
		return 0;

	inside_token = 0;
	ntok = 0;
	while (*str) {
		if ((*str) == sep) {
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

/*--------------------------------------------------------------------------*/


int set_prefix_ip_len(struct radv_prefix *prefix, char *str_ip, char *str_len, int lineno)
{
	if (inet_ptonn(AF_INET6, str_ip, &prefix->Prefix) < 0) {
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Invalid prefix %s/%s at line: %d\n", str_ip, str_len, lineno) );
		return 0;
	}
	if (str_to_char( (u8_t *) & prefix->PrefixLen, str_len) == 0) {
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Invalid prefix %s/%s at line: %d\n", str_ip, str_len, lineno) );
		return 0;
	}
	return 1;
}

int set_prefix_option(struct radv_prefix *prefix, char *option, char *val, int lineno)
{
	if (strcmp(option, "AdvOnLinkFlag") == 0) {
		if (str_to_bool( & prefix->AdvOnLinkFlag, val) == 1)
			return 1;
	} else
	if (strcmp(option, "AdvAutonomousFlag") == 0) {
		if (str_to_bool( & prefix->AdvAutonomousFlag, val) == 1)
			return 1;

	} else             
	if (strcmp(option, "AdvValidLifetime") == 0) {
		if (str_to_int_or_infinity( & prefix->AdvValidLifetime, val) == 1)
			return 1;

	} else
	if (strcmp(option, "AdvPreferredLifetime") == 0) {
		if (str_to_int_or_infinity( & prefix->AdvPreferredLifetime, val) == 1)
			return 1;
	} 
	else {
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Unknown option '%s' \n", option) );
	}

	LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Wrong value '%s' for '%s' at line '%d'\n", val, option, lineno) );


	return 0;
}	

int set_netif_prefix(struct netif *netif, char *val, int lineno)
{
	char *tokens[31];
	int  num, i, err;
	struct radv_prefix *prefix; 

	prefix = radv_prefix_list_alloc();
	if (prefix == NULL)
		return 0;

	/*
	 * 2001:1234:5678::/64 , Option1 = val, Option2 = val, ....
	 *      token 0             token 0       token 0
	 */
	err = 0;
	if ((num=tokenize(val, tokens, 30, ',')) >= 1 ) {

		for (i=0; i<num; i++) {

			/*
			 * <prefix>  '/'  <len>
			 */
			if (i==0) {                             
				char *pref_tok[3];
				if (tokenize(GETTOK(num, tokens, i), pref_tok, 2, '/') != 2) {
					LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Error while parsing '%s' at line: %d\n", GETTOK(num, tokens, i), lineno));
					err = 1;
					break;
				}
				
				if (set_prefix_ip_len(prefix,  str_strip(pref_tok[0]),  str_strip(pref_tok[1]), lineno) == 0)
					err = 1;
			}
			/*
			 * Option  '='  <val>
			 */
			else {
				char *opt_tok[3];
				if (tokenize(GETTOK(num, tokens, i), opt_tok, 2, '=') != 2) {
					LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Error while parsing '%s' at line: %d\n", GETTOK(num, tokens, i), lineno) );
					err = 1;
					break;
				}

				if (set_prefix_option(prefix, str_strip(opt_tok[0]), str_strip(opt_tok[1]), lineno) == 0)
					err = 1;
			}
			
		}
	}
	else {
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("Error while parsing line: %d\n", lineno) );
	       	err = 1;
	}

	if (err) {
		radv_prefix_list_free(prefix);
		return 0;
	}

	ip_addr_debug_print(IP_RADVCONF_DEBUG, &prefix->Prefix);


	prefix->next = netif->radv.prefix_list;
	netif->radv.prefix_list =  prefix;
	
	return 1;
}

int set_netif_parameter(struct netif *netif, char *parameter, char *val, int lineno)
{
	struct radv *rinfo = &(netif->radv);

	if (strcmp(parameter, "AdvSendAdvert") == 0) {
		if (str_to_bool( &rinfo->AdvSendAdvert , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "MaxRtrAdvInterval") == 0) {
		if (str_to_int( &rinfo->MaxRtrAdvInterval , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "MinRtrAdvInterval") == 0) {
		if (str_to_int( &rinfo->MinRtrAdvInterval , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "MinDelayBetweenRAs") == 0) {
		if (str_to_int( &rinfo->MinDelayBetweenRAs , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvManagedFlag") == 0) {
		if (str_to_bool( &rinfo->AdvManagedFlag , val) == 0)
			return 1;

	} else 
	if (strcmp(parameter, "AdvOtherConfigFlag") == 0) {
		if (str_to_bool( &rinfo->AdvOtherConfigFlag , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvLinkMTU") == 0) {
		if (str_to_int( &rinfo->AdvLinkMTU , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvReachableTime") == 0) {
		if (str_to_int( &rinfo->AdvReachableTime , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvRetransTimer") == 0) {
		if (str_to_int( &rinfo->AdvRetransTimer , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvCurHopLimit") == 0) {
		if (str_to_char( &rinfo->AdvCurHopLimit , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvDefaultLifetime") == 0) {
		if (str_to_short( &rinfo->AdvDefaultLifetime , val) == 1)
			return 1;

	} else 
	if (strcmp(parameter, "AdvSourceLLAddress") == 0) {
		if (str_to_bool( &rinfo->AdvSourceLLAddress , val) == 1)
			return 1;
	
	} else 
	if (strcmp(parameter, "UnicastOnly") == 0) {
		if (str_to_bool( &rinfo->UnicastOnly , val) == 1)
			return 1;

	} else 
	/*
	 * Prefix options
	 */
	if (strcmp(parameter, "AddPrefix") == 0) {

		return set_netif_prefix(netif, val, lineno);

	} else 
	/*
	 * Others
	 */
	{
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("%s: unknown option '%s' at line: %d\n", __func__, parameter, lineno));
		return 0;
	}


	LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("%s: invalid value '%s' for '%s' at line: %d\n", __func__, val, parameter, lineno));
	return 0;
}



/*--------------------------------------------------------------------------*/

int radv_load_configfile(char *path)
{
	char        lin[ASCIILINESZ+1];
	char        sec[ASCIILINESZ+1];
	char        key[ASCIILINESZ+1];
	char        val[ASCIILINESZ+1];
	char    *   where ;
	FILE    *   filein ;
	int         lineno ;

	struct netif * curr_netif;

	if ((filein=fopen(path, "r"))==NULL) {
		LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("%s: file '%s' not found!\n", __func__, path));

		return 0;
	}

	sec[0]=0;
	
	/*
	* Initialize a new dictionary entry
	*/
	lineno = 0 ;

	curr_netif = NULL;
	
	while (fgets(lin, ASCIILINESZ, filein) != NULL) {

		lineno++ ;

		where = strskp(lin); /* Skip leading spaces */

		/* 
		 * # Comment.
		 */
		if (*where==';' || *where=='#' || *where==0)
			continue ; /* Comment lines */
		else 
		/* 
		 * [vd0]
		 */
		if (sscanf(where, "[%[^]]", sec) == 1) {
			/* Valid section name */
			strcpy(sec, strlwc(sec));

			if (curr_netif != NULL) {
				ip_radv_check_options(curr_netif);
				
				// FIX: check values
			}

			curr_netif = netif_find(sec);
			if (curr_netif == NULL) {
				LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("%s: netif '%s' not found! (line %d)\n", __func__, sec, lineno));
			}
		} 
		/* 
		 * Parameter = Value
		 */
		else if (sscanf (where, "%[^=] = %[^;#]",     key, val) == 2) {

			if (curr_netif == NULL) {
				LWIP_DEBUGF(IP_RADVCONF_DEBUG, ("%s: interface not specified!\n", __func__));
				continue;
			}
			strcpy(key, strcrop(key));
			strcpy(val, strcrop(val));

			set_netif_parameter(curr_netif, key, val, lineno);
		}
	}

	if (curr_netif != NULL) {
		ip_radv_check_options(curr_netif);

		// FIX: check values
	}

	fclose(filein);

	return 1 ;
}

#endif

