/* ----------------------------------------------------------------------- *
 *   
 *   Copyright Renzo Davoli 2005 
 *   From: zisofs-tools Copyright 2001 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef ZISOFS_H
#define ZISOFS_H
/* zisofs definitions */

#ifndef CBLOCK_SIZE_LG2
#define CBLOCK_SIZE_LG2	15	/* Compressed block size */
#endif
#define CBLOCK_SIZE	(1 << CBLOCK_SIZE_LG2)

/* VERY VERY VERY IMPORTANT: Must be a multiple of 4 bytes */
struct compressed_file_header {
  char magic[8];
  char uncompressed_len[4];
  unsigned char header_size;
  unsigned char block_size;
  char reserved[2];		/* Reserved for future use, MBZ */
};

#endif
