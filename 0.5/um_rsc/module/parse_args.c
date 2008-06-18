/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   parse_args.c: parse module arguments functions 
 *   
 *   Copyright (C) 2007 Andrea Forni
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "parse_args.h"
#include "gdebug.h"

/* Local Functions */
enum err_return_value {
  OPT_ERR_OK = 0,
  OPT_ERR_ARG_ZERO_LENGTH,
  OPT_ERR_ARG_NEEDED,
  OPT_ERR_ARG_POINTLESS,
  OPT_ERR_OPT_NOT_FOUND,
  OPT_ERR_LAST = OPT_ERR_OPT_NOT_FOUND
};

static char *err2str[] = {
  NULL,
  "the argument has zero length",
  "the option needs an argument",
  "the option doesn't need an argument",
  "option not found"
};

/* The function parse the single option, saving it value, if present, in ->var. 
 * On success return 0, otherwise an error OPT_ERR_* defined in the header. */
static int rsc_parse_single_opt(char *str, int len, struct rsc_option opt[], int opt_len) {
  int i;
  char *c;
  char *name = str;
  int name_len = 0;
  char *arg = NULL;
  
  if ( (c = strchr(str, '=')) != NULL ) {
    /* "str" contains an option with '=' */
    name_len = len - strlen(c);
    arg = c + 1;
  } else {
    /* "str" contains an option without arguments */
    name_len = len;
    arg = NULL;
  }

  GDEBUG(2, "rsc_parse_opt: Name = '%s', name len = %d, arg = '%s'\n", name, name_len, arg);
  
  /* Now I have to search the right option */
  for(i = 0; i < opt_len; i++) {
    if(strncmp(name, opt[i].name, name_len) == 0) {
      /* Found the option */
      GDEBUG(2, "rsc_parse_opt: Option '%s' found in '%s'\n", opt[i].name, name);
      /* This option need an argument but there isn't */
      if( opt[i].has_arg == 1 && arg == NULL ) return OPT_ERR_ARG_NEEDED;
      /* This option doesn't need an argument but there is */
      if( opt[i].has_arg == 0 && arg != NULL ) return OPT_ERR_ARG_POINTLESS;

      /* Parse the argument, if there is */
      if (opt[i].has_arg == 1 ) {
        int arg_len = strlen(arg);
        
        /* If the argument has zero length, return */
        if(arg_len == 0) return OPT_ERR_ARG_ZERO_LENGTH;

        /* The '+1' in the length of the string in malloc() or bxzero() is ofr
         * the final '\0'. */
		    *(opt[i].var) = (char *) malloc( ( arg_len + 1) * sizeof(char) );
		    bzero(*(opt[i].var), arg_len + 1);
		    strncpy(*(opt[i].var), arg, arg_len);
		
	    } else {
	      *(opt[i].var) = OPT_PRESENT;
	    }
		
	    GDEBUG(2, "rsc_parse_opt: Option name = '%s',  option argument = '%s' (len = %d, addr = %p)\n", opt[i].name, *(opt[i].var), strlen(*(opt[i].var)), opt[i].var);
	
      /* I found the option, I can exit. */
      break;
    }
  }

  /* No option foun with name 'name' */
  if ( i == opt_len ) return OPT_ERR_OPT_NOT_FOUND;

  return OPT_ERR_OK;
}

/* Global Functions */

/* Parse all the arguments in "init_args".
 * If there is an error a number != 0 is returned.*/
int rsc_parse_opt(char *init_args, struct rsc_option opt[], int opt_len) {
  int len_str, i, ret;
  int first;
  char *str;
  
  len_str = strlen(init_args);
  GDEBUG(2, "rsc_parse_opt: Initargs: \"%s\" (len = %d), opt_len = %d\n", init_args, len_str, opt_len);

  /* If there is no arguments (len_str == 0), I return */
  if(len_str == 0) return OPT_ERR_OK;
  
  /* I split the string into the different options, ten I parse
   * each option. */
  for(first = i = 0; i < len_str; i++) {
    
    if( (init_args[i] == ',') || (i == len_str - 1) ) {
      /* End of an option OR last option. I parse it */
      int len = (i == len_str - 1 ) ? (i - first + 1) : (i - first);
      int dim = len * sizeof(char) + 1;

      /* I create a string of the single option ... */
      str = (char *) malloc( dim );
      bzero(str, dim);
      strncpy(str, init_args + first, len);

      /* ... and I parse it. */
      ret = rsc_parse_single_opt(str, len, opt, opt_len);
      free(str);
      /* If an error occurs, return */
      if( ret != 0) return ret;

      first = i + 1;
    }
  }

  return OPT_ERR_OK;
}

char *rsc_parse_to_string(int err) {
  if( err >= OPT_ERR_OK && err <= OPT_ERR_LAST )
    return err2str[err];
  else
    return NULL;
}
