/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   scmap: map for system call wrappers
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
 *
 *   $Id$
 *
 */   

#include <unistd.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include "defs.h"
#include "scmap.h"

int scmap_scmapsize;
int scmap_sockmapsize;

serfunt choice_path, choice_link, choice_fd, choice_socket, choice_link2;
serfunt always_umnone, choice_mount;
wrapinfun wrap_in_getcwd, wrap_in_chdir, wrap_in_fchdir;
wrapinfun wrap_in_open, wrap_in_read, wrap_in_write, wrap_in_close;
wrapinfun wrap_in_select, wrap_in_poll, wrap_in_ioctl;
wrapinfun wrap_in_readv, wrap_in_writev;
wrapinfun wrap_in_stat, wrap_in_fstat;
wrapinfun wrap_in_stat64, wrap_in_fstat64;
wrapinfun wrap_in_readlink, wrap_in_getdents, wrap_in_access;
wrapinfun wrap_in_fcntl, wrap_in_notsupp, wrap_in_llseek, wrap_in_lseek;
wrapinfun wrap_in_mkdir, wrap_in_unlink, wrap_in_chown, wrap_in_fchown;
wrapinfun wrap_in_chmod, wrap_in_fchmod, wrap_in_dup, wrap_in_fsync;
wrapinfun wrap_in_link, wrap_in_symlink, wrap_in_pread, wrap_in_pwrite;
wrapinfun wrap_in_utime, wrap_in_mount, wrap_in_umount;
wrapinfun wrap_in_umask, wrap_in_chroot;

wrapoutfun wrap_out_open, wrap_out_std, wrap_out_close, wrap_out_chdir;
wrapoutfun wrap_out_dup, wrap_out_select, wrap_out_poll, wrap_out_fcntl;

#ifdef PIVOTING_TEST
wrapinfun wrap_in_getpid;
wrapoutfun wrap_out_getpid;
#endif

struct sc_map scmap[]={
	{__NR_chdir,	choice_path,	wrap_in_chdir,	wrap_out_chdir, ALWAYS,	1},
	{__NR_fchdir,	choice_fd,	wrap_in_fchdir,	wrap_out_chdir, ALWAYS,	1},
	{__NR_getcwd,	always_umnone,
					wrap_in_getcwd,	wrap_out_std,	ALWAYS,	2},
	{__NR_open,	choice_path,	wrap_in_open,	wrap_out_open,	ALWAYS,	4},
	{__NR_creat,	choice_path,    wrap_in_open,   wrap_out_open,	ALWAYS,	2},
	{__NR_close,	choice_fd,	wrap_in_close,	wrap_out_close,	ALWAYS,	1},
	{__NR_select,	always_umnone,	wrap_in_select,	wrap_out_select,ALWAYS,	5},
	{__NR_poll,	always_umnone,	wrap_in_poll,	wrap_out_poll,  ALWAYS,	3},
	{__NR__newselect,always_umnone,	wrap_in_select,	wrap_out_select,ALWAYS,	5},
	{__NR_umask,	always_umnone,	wrap_in_umask,  wrap_out_std,	ALWAYS,	1},
	{__NR_chroot,	always_umnone,	wrap_in_chroot, wrap_out_std,	ALWAYS,	1},
	{__NR_dup,	choice_fd,	wrap_in_dup, wrap_out_dup,	ALWAYS,	1},
	{__NR_dup2,	choice_fd,	wrap_in_dup, wrap_out_dup,	ALWAYS,	2},
	{__NR_mount,	choice_mount,	wrap_in_mount,	wrap_out_std,	0,	5},
	{__NR_umount,	choice_path,	wrap_in_umount,	wrap_out_std,	0,	1},
	{__NR_umount2,	choice_path,	wrap_in_umount,	wrap_out_std,	0,	2},
	{__NR_ioctl,	choice_fd,	wrap_in_ioctl,	wrap_out_std, 	0,	3},
	{__NR_read,	choice_fd,	wrap_in_read,	wrap_out_std,	0,	3},
	{__NR_write,	choice_fd,	wrap_in_write,	wrap_out_std,	0,	3},
	{__NR_readv,	choice_fd,	wrap_in_readv,	wrap_out_std,	0,	3},
	{__NR_writev,	choice_fd,	wrap_in_writev,	wrap_out_std,	0,	3},
	{__NR_stat,	choice_path,	wrap_in_stat,	wrap_out_std,	0,	2},
	{__NR_lstat,	choice_link,	wrap_in_stat,	wrap_out_std,	0,	2},
	{__NR_fstat,	choice_fd,	wrap_in_fstat,	wrap_out_std,	0,	2},
	{__NR_stat64,	choice_path,	wrap_in_stat64,	wrap_out_std,	0,	2},
	{__NR_lstat64,	choice_link,	wrap_in_stat64,	wrap_out_std,	0,	2},
	{__NR_fstat64,	choice_fd,	wrap_in_fstat64,wrap_out_std,	0,	2},
	{__NR_chown,	choice_path,	wrap_in_chown, wrap_out_std,	0,	3},
	{__NR_lchown,	choice_link,	wrap_in_chown, wrap_out_std,	0,	3},
	{__NR_fchown,	choice_fd,	wrap_in_fchown, wrap_out_std,	0,	3},
	{__NR_chmod,	choice_path,	wrap_in_chmod, wrap_out_std,	0,	2},
	{__NR_fchmod,	choice_fd,	wrap_in_fchmod, wrap_out_std,	0,	2},
	{__NR_getxattr,	choice_path,	wrap_in_notsupp, wrap_out_std,	0,	4},
	{__NR_lgetxattr,choice_link,	wrap_in_notsupp, wrap_out_std,	0,	4},
	{__NR_fgetxattr,choice_fd,	wrap_in_notsupp, wrap_out_std,	0,	4},
	{__NR_readlink,	choice_link,	wrap_in_readlink,wrap_out_std,	0,	3},
	{__NR_getdents,	choice_fd,	wrap_in_getdents,wrap_out_std,	0,	3},
	{__NR_getdents64,choice_fd,	wrap_in_getdents,wrap_out_std,	0,	3},
	{__NR_access,	choice_path,	wrap_in_access, wrap_out_std,	0,	2},
	{__NR_fcntl,	choice_fd,	wrap_in_fcntl, wrap_out_fcntl,	0,	3},
	{__NR_fcntl64,	choice_fd,	wrap_in_fcntl, wrap_out_fcntl,	0,	3},
	{__NR_lseek,	choice_fd,	wrap_in_lseek, wrap_out_std,	0,	3},
	{__NR__llseek,	choice_fd,	wrap_in_llseek, wrap_out_std,	0,	5},
	{__NR_mkdir,	choice_link,	wrap_in_mkdir, wrap_out_std,	0,	2},
	{__NR_rmdir,	choice_path,	wrap_in_unlink, wrap_out_std,	0,	1},
	{__NR_link,	choice_link2,	wrap_in_link, wrap_out_std,	0,	2},
	{__NR_symlink,	choice_link2,	wrap_in_symlink, wrap_out_std,	0,	2},
	{__NR_unlink,	choice_path,	wrap_in_unlink, wrap_out_std,	0,	1},
	{__NR_statfs,	choice_path,	wrap_in_notsupp, wrap_out_std,	0,	2},
	{__NR_fstatfs,	choice_fd,	wrap_in_notsupp, wrap_out_std,	0,	2},
	{__NR_utime,	choice_path,	wrap_in_utime, wrap_out_std,	0,	2},
	{__NR_utimes,	choice_path,	wrap_in_utime, wrap_out_std,	0,	2},
	{__NR_fsync,	choice_fd,	wrap_in_fsync, wrap_out_std,	0,	1},
	{__NR_fdatasync,choice_fd,	wrap_in_fsync, wrap_out_std,	0,	1},
#ifdef __NR_pread64
	{__NR_pread64,	choice_fd,	wrap_in_pread, 	wrap_out_std,	0,	5},
#else
	{__NR_pread,	choice_fd,	wrap_in_pread, 	wrap_out_std,	0,	5},
#endif
#ifdef __NR_pwrite64
	{__NR_pwrite64,	choice_fd,	wrap_in_pwrite, wrap_out_std,	0,	5},
#else
	{__NR_pwrite,	choice_fd,	wrap_in_pwrite, wrap_out_std,	0,	5},
#endif
#ifdef PIVOTING_TEST
	{__NR_getpid,	always_umnone,	wrap_in_getpid, wrap_out_getpid,ALWAYS,	0},
#endif
};

#define SIZESCMAP (sizeof(scmap)/sizeof(struct sc_map))

intfunt wrap_in_socket, wrap_out_socket;
intfunt wrap_in_bind_connect, wrap_in_listen, wrap_in_getsock, wrap_in_send;
intfunt wrap_in_recv, wrap_in_shutdown, wrap_in_setsockopt, wrap_in_getsockopt;
intfunt wrap_in_sendmsg, wrap_in_recvmsg, wrap_in_accept;
intfunt wrap_in_sendto, wrap_in_recvfrom;

struct sc_map sockmap[]={
	{0,			NULL,		NULL,			NULL,	0,	0},
/* 1*/	{SYS_SOCKET,    	choice_socket, 	wrap_in_socket,		wrap_out_socket,	0,	3}, 
/* 2*/	{SYS_BIND,      	choice_fd,	wrap_in_bind_connect,	wrap_out_std,	0,	3},
/* 3*/	{SYS_CONNECT,   	choice_fd,	wrap_in_bind_connect,	wrap_out_std,	0,	3},
/* 4*/	{SYS_LISTEN,    	choice_fd,	wrap_in_listen,		wrap_out_std,	0,	2},
/* 5*/	{SYS_ACCEPT,    	choice_fd,	wrap_in_accept,		wrap_out_socket,	CB_R,	3},
/* 6*/	{SYS_GETSOCKNAME,       choice_fd,	wrap_in_getsock,	wrap_out_std,	0,	3},
/* 7*/	{SYS_GETPEERNAME,       choice_fd,	wrap_in_getsock,	wrap_out_std,	0,	3},
/* 8*/	{SYS_SOCKETPAIR,        0,		NULL, 			NULL,	0,	4}, /* not used */
/* 9*/	{SYS_SEND,      	choice_fd,	wrap_in_send,		wrap_out_std,	0,	4},
/*10*/	{SYS_RECV,      	choice_fd,	wrap_in_recv,		wrap_out_std,	0,	4},
/*11*/	{SYS_SENDTO,    	choice_fd,	wrap_in_sendto,		wrap_out_std,	0,	6},
/*12*/	{SYS_RECVFROM,  	choice_fd,	wrap_in_recvfrom,	wrap_out_std,	0,	6},
/*13*/	{SYS_SHUTDOWN,  	choice_fd,	wrap_in_shutdown,	wrap_out_std,	0,	2},
/*14*/	{SYS_SETSOCKOPT,        choice_fd,	wrap_in_setsockopt,	wrap_out_std,	0,	5},
/*15*/	{SYS_GETSOCKOPT,        choice_fd,	wrap_in_getsockopt,	wrap_out_std,	0,	5},
/*16*/	{SYS_SENDMSG,   	choice_fd,	wrap_in_sendmsg,	wrap_out_std,	0,	3},
/*17*/	{SYS_RECVMSG,   	choice_fd,	wrap_in_recvmsg,	wrap_out_std,	0,	3}
};
#define SIZESOCKMAP (sizeof(sockmap)/sizeof(struct sc_map))

static short scremap[MAXSC];
static short scuremap[MAXUSC];

void init_scmap()
{
	register int i;

	for (i=0; i<SIZESCMAP; i++) {
		int scno=scmap[i].scno;
		if (scno > 0 && scno < MAXSC)
			scremap[scno]=i;
		else if (scno >= BASEUSC && scno < BASEUSC+MAXUSC)
			scuremap[scno-BASEUSC]=i;
	}
	scmap_scmapsize = SIZESCMAP;
	scmap_sockmapsize = SIZESOCKMAP;
}

int uscno(int scno)
{
	if (scno > 0 && scno < MAXSC)
		return scremap[scno];
	else if (scno >= BASEUSC && scno < BASEUSC+MAXUSC)
		return scuremap[scno-BASEUSC];
	else
		return -1;
}
