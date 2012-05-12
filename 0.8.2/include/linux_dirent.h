#ifndef _LINUX_DIRENT_H
#define _LINUX_DIRENT_H

struct dirent {
	long    d_ino;
	__kernel_off_t  d_off;
	unsigned short  d_reclen;
	char    d_name[256]; /* We must not include limits.h! */
};

struct dirent64 {
	__u64   d_ino;
	__s64   d_off;
	unsigned short  d_reclen;
	unsigned char d_type;
	char    d_name[256];
};

enum
{
	DT_UNKNOWN = 0,
# define DT_UNKNOWN DT_UNKNOWN
	DT_FIFO = 1,
# define DT_FIFO  DT_FIFO
	DT_CHR = 2,
# define DT_CHR   DT_CHR
	DT_DIR = 4,
# define DT_DIR   DT_DIR
	DT_BLK = 6,
# define DT_BLK   DT_BLK
	DT_REG = 8,
# define DT_REG   DT_REG
	DT_LNK = 10,
# define DT_LNK   DT_LNK
	DT_SOCK = 12,
# define DT_SOCK  DT_SOCK
	DT_WHT = 14
# define DT_WHT   DT_WHT
};

#endif

