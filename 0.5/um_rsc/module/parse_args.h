/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   parse_args.h: parse module arguments functions 
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

#ifndef __PARSE_ARG_HEADDER__
#define __PARSE_ARG_HEADDER__

#define OPT_PRESENT "1"

struct rsc_option {
  char *name;       /* The name of the option */
  int has_arg;      /* It's equal to 1 if the option as an argument, 0 otherwise */
  char **var;        /* If ->as_arg it's equal to 1, the variable store the value of 
                       the argument. Otherwise if ->as_arg it's equal to 0,
                       ->var it's equal to the string OPT_PRESENT if the option it's 
                       present in the list of option to parse, otherwsie it's left 
                       unchanged. */
};

/* Return value */

char *rsc_parse_to_string(int err);
int rsc_parse_opt(char *init_args, struct rsc_option opt[], int opt_len);

#endif /* __PARSE_ARG_HEADDER__ */
