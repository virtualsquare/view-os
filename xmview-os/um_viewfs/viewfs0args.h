/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   viewfs parameters management
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Paolo Angelelli, Andrea Seraghiti
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
 *
 */

#ifndef _VIEWFS0ARG
#define _VIEWFS0ARG
#define VIEWFS_DEBUG 1<<29 
#define VIEWFS_MOVE  0x00
#define VIEWFS_MERGE 0x01
#define VIEWFS_COW   0x02 
#define VIEWFS_MINCOW 0x10
#define VIEWFS_RENEW 0x100 

int viewfsarg(char *opts,int *pflags,char ***pexceptions);
#endif
