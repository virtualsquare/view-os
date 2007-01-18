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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <linux/fs.h>
#include <config.h>
#include "mbr.h"
#define IDE_HEADER_OFFSET 446

static char mbrsignature[2]={0x55,0xAA};

struct mbr_header {
	struct mbrpart {
		char flags;
		char chs_begin[3];
		char type;
		char chs_end[3];
		char lba_begin[4];
		char lba_noblocks[4];
	} mbrpart[4];
	char signature[2];
};

#define LE32_INT(X) (((X)[0])+(((X)[1])<<8)+(((X)[2])<<16)+(((X)[3])<<24))

static void maxgeom(struct hd_geometry *geom, const char *chs)
{
	unsigned char s,h;
	unsigned short c;
	h=(unsigned char)chs[0];
	s=((unsigned char)chs[1]) & 0x3f;
	c=((unsigned char)chs[2]) + (((unsigned char)chs[1]) & 0xc0) << 2;
	if ((h+1) > geom->heads)
		geom->heads = h+1;
	if (s > geom->sectors)
		geom->sectors = s;
	if (c > geom->cylinders)
		geom->cylinders = c;
}

static void mbr_read(struct mbr *mbr)
{
	struct mbr_header mbr_header;
	unsigned int ext_part_base=0;
	pread64(mbr->fd, &mbr_header, sizeof(mbr_header), (off_t)IDE_HEADER_OFFSET);
	if (memcmp(mbr_header.signature,mbrsignature,2) != 0) {
		fprintf(stderr,"bad signature in MBR %x %x\n",
				mbr_header.signature[0],mbr_header.signature[1]);
	} else {
		/* MBR is okay. Read MBR */
		int i;
		unsigned int offset=0;
		memset(&(mbr->geometry),0,sizeof(struct hd_geometry));
		for (i=0;i<4;i++) {
			if(mbr_header.mbrpart[i].type != 0) {
				struct partition *new=mbr->part[i]=malloc(sizeof(struct partition));
				maxgeom(&(mbr->geometry),mbr_header.mbrpart[i].chs_end);
				new->flags=mbr_header.mbrpart[i].flags;
				new->type=mbr_header.mbrpart[i].type;
				new->LBAbegin=LE32_INT(mbr_header.mbrpart[i].lba_begin);
				new->LBAnoblocks=LE32_INT(mbr_header.mbrpart[i].lba_noblocks);
				if(mbr_header.mbrpart[i].type == 5) {/* extended partition*/
					if (ext_part_base==0) 
						ext_part_base=new->LBAbegin;
					else
						fprintf(stderr,"There are more than one extended partitions against the specifications\n");
				}
			}
		}
		if (mbr->geometry.heads == 0)
			mbr->geometry.heads = 255;
		if (mbr->geometry.sectors == 0)
			mbr->geometry.sectors = 63;
		mbr->geometry.cylinders = (mbr->size >> IDE_BLOCKSIZE_LOG) / (mbr->geometry.heads * mbr->geometry.sectors);


		/* Read the chain of logical partitions insmbr the extended partition */
		while (ext_part_base > 0) {
			off_t base=((off_t)(ext_part_base+offset)) << IDE_BLOCKSIZE_LOG;
			pread64(mbr->fd, &mbr_header, sizeof(mbr_header), (base+IDE_HEADER_OFFSET));
			if (memcmp(mbr_header.signature,mbrsignature,2) != 0) {
				fprintf(stderr,"bad signature in block %d=%x %x\n",base,
						mbr_header.signature[0],mbr_header.signature[1]);
				ext_part_base=0;
			} else {
				if(mbr_header.mbrpart[0].type != 0) {
					struct partition *new=mbr->part[i]=malloc(sizeof(struct partition));
					new->flags=mbr_header.mbrpart[0].flags;
					new->type=mbr_header.mbrpart[0].type;
					new->LBAbegin=LE32_INT(mbr_header.mbrpart[0].lba_begin)+ext_part_base+offset;
					new->LBAnoblocks=LE32_INT(mbr_header.mbrpart[0].lba_noblocks);
					i++;
				}
				if(mbr_header.mbrpart[1].type == 5) 
					offset=LE32_INT(mbr_header.mbrpart[1].lba_begin);
				else
					ext_part_base=0;
			}
		}
	}
}
	
void mbr_printpt(struct mbr *mbr)
{
	int i;
	for(i=0;i<IDE_MAXPART;i++) {
		if (mbr->part[i]) {
			fprintf(stderr,"PART %-2d F%02x T%02x B=%10d S=%10d\n",i,
					mbr->part[i]->flags,mbr->part[i]->type,mbr->part[i]->LBAbegin,mbr->part[i]->LBAnoblocks);
		}
	}
}

void mbr_reread(struct mbr *mbr)
{
	int i;
	for(i=0;i<IDE_MAXPART;i++) {
		if (mbr->part[i]) {
			free(mbr->part[i]);
			mbr->part[i]=0;
		}
	}
	mbr_read(mbr);
}

struct mbr *mbr_open(int fd)
{
	off_t size=lseek(fd,0,SEEK_END);
	if (size < 0) {
		/* maybe it is a device */
		long long lsize=-1;
		if (ioctl(fd,BLKGETSIZE64,&lsize) >= 0)
			size=lsize;
	}
	if (size > 0) {
		struct mbr *mbr=calloc(1,sizeof(struct mbr));
		mbr->fd=fd;
		mbr->size=size;
		mbr_read(mbr);
		return mbr;
	} else {
		return NULL;
	}
}

void mbr_close(struct mbr *mbr)
{
	close(mbr->fd);
	free(mbr);
}
