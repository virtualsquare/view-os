/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   MBR: Library to read MBR and Extended MBR
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
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

#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<linux/hdreg.h>

#define IDE_MAXPART 63
#define IDE_BLOCKSIZE 512
#define IDE_BLOCKSIZE_LOG 9

struct partition {
	int flags;
	char type;
	unsigned int LBAbegin;
	unsigned int LBAnoblocks;
};

struct mbr {
	int fd;
	off_t size;
	struct hd_geometry geometry;
	struct partition *part[IDE_MAXPART];
};

void mbr_printpt(struct mbr *mbr);
void mbr_reread(struct mbr *mbr);
struct mbr *mbr_open(int fd);
void mbr_close(struct mbr *mbr);
