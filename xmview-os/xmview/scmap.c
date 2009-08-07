/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   scmap: map for system call wrappers
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
 *   $Id$
 *
 */   

#include <unistd.h>
#include <asm/unistd.h>
#include <linux/net.h>
#include <config.h>
#include "defs.h"
#include "scmap.h"
#include "uid16to32.h"

int scmap_scmapsize;
int scmap_sockmapsize;
int scmap_virscmapsize;

htfunt choice_path, choice_link, choice_fd, choice_socket, choice_link2;
htfunt choice_sockpath;
htfunt choice_pathat, choice_linkat, choice_pl5at, choice_pl4at, choice_link3at;
htfunt choice_link2at, choice_unlinkat;
htfunt always_null, choice_mount, choice_sc;
#ifdef _UM_MMAP
htfunt choice_mmap;
#endif
wrapinfun wrap_in_getcwd, wrap_in_chdir, wrap_in_fchdir;
wrapinfun wrap_in_open, wrap_in_read, wrap_in_write, wrap_in_close;
wrapinfun wrap_in_select, wrap_in_poll, wrap_in_ioctl;
wrapinfun wrap_in_readv, wrap_in_writev;
wrapinfun wrap_in_stat, wrap_in_fstat;
wrapinfun wrap_in_stat64, wrap_in_fstat64;
wrapinfun wrap_in_getxattr;
wrapinfun wrap_in_readlink, wrap_in_getdents,wrap_in_getdents64, wrap_in_access;
wrapinfun wrap_in_fcntl, wrap_in_notsupp, wrap_in_llseek, wrap_in_lseek;
wrapinfun wrap_in_mkdir, wrap_in_unlink, wrap_in_chown, wrap_in_fchown;
wrapinfun wrap_in_chmod, wrap_in_fchmod, wrap_in_dup, wrap_in_fsync;
wrapinfun wrap_in_link, wrap_in_symlink, wrap_in_pread, wrap_in_pwrite;
wrapinfun wrap_in_utime, wrap_in_mount, wrap_in_umount,wrap_in_umount2;
wrapinfun wrap_in_umask, wrap_in_chroot, wrap_in_mknod;
wrapinfun wrap_in_truncate, wrap_in_ftruncate, wrap_in_execve;
wrapinfun wrap_in_statfs, wrap_in_fstatfs;

/* XXX: find a better way (see defs_x86_64*.h) */
#if __NR_statfs64 != __NR_doesnotexist
wrapinfun wrap_in_statfs64, wrap_in_fstatfs64;
#endif

#ifdef _UM_MMAP
wrapinfun wrap_in_mmap,wrap_in_mremap,wrap_in_munmap;
#endif
wrapinfun wrap_in_kill;
wrapinfun wrap_in_getxid16,wrap_in_setuid16, wrap_in_setgid16;
wrapinfun wrap_in_getxid,wrap_in_setuid,wrap_in_setreuid;
wrapinfun wrap_in_getresuid, wrap_in_setresuid,wrap_in_setgid;
wrapinfun wrap_in_getresgid, wrap_in_setresgid,wrap_in_setregid;
wrapinfun wrap_in_nice, wrap_in_getpriority, wrap_in_setpriority;
wrapinfun wrap_in_getpid, wrap_in_setpid, wrap_in_getpid_1, wrap_in_setpgid;
wrapinfun wrap_in_getpgrp, wrap_in_setpgrp;

wrapoutfun wrap_out_open, wrap_out_std, wrap_out_close, wrap_out_chdir;
wrapoutfun wrap_out_dup, wrap_out_select, wrap_out_poll, wrap_out_fcntl;
wrapoutfun wrap_out_execve;
#ifdef _UM_MMAP
wrapoutfun wrap_out_mmap,wrap_out_mremap,wrap_out_munmap;
#endif
wrapoutfun wrap_out_kill;
wrapoutfun wrap_out_chroot;

htfunt nchoice_fd, nchoice_sfd, nchoice_sc, nchoice_mount, nchoice_path, nchoice_link, nchoice_link2, nchoice_socket;
htfunt nchoice_sockpath;
htfunt nchoice_pathat, nchoice_linkat, nchoice_pl5at, nchoice_pl4at, nchoice_link3at;
htfunt nchoice_link2at, nchoice_unlinkat;

wrapfun nw_syspath_std,nw_sysfd_std,nw_sockfd_std,nw_sysopen,nw_syslink,nw_syssymlink, nw_notsupp;
wrapfun nw_sysdup,nw_sysclose;
wrapfun nw_sysstatfs64,nw_sysfstatfs64;
wrapfun nw_socket,nw_msocket,nw_accept;
wrapfun nw_sysatpath_std;

wrapinfun wrap_in_socket, wrap_out_socket;
wrapinfun wrap_in_bind_connect, wrap_in_listen, wrap_in_getsock, wrap_in_send;
wrapinfun wrap_in_recv, wrap_in_shutdown, wrap_in_setsockopt, wrap_in_getsockopt;
wrapinfun wrap_in_sendmsg, wrap_in_recvmsg, wrap_in_accept;
wrapinfun wrap_in_msocket;
wrapinfun wrap_in_sendto, wrap_in_recvfrom;
wrapinfun wrap_in_umservice, wrap_out_umservice;
wrapinfun wrap_in_time, wrap_in_gettimeofday, wrap_in_settimeofday;
wrapinfun wrap_in_adjtimex, wrap_in_clock_gettime, wrap_in_clock_settime;
wrapinfun wrap_in_clock_getres;
wrapinfun wrap_in_uname, wrap_in_gethostname, wrap_in_sethostname;

/* we should keep this structure unique. the indexes can be used to forward
 * the call on a different computer.*/

#if (__NR_socketcall != __NR_doesnotexist)
	#define __NR_socket	SYS_SOCKET
	#define	__NR_bind	SYS_BIND
	#define	__NR_connect	SYS_CONNECT
	#define	__NR_listen	SYS_LISTEN
	#define	__NR_accept	SYS_ACCEPT
#ifdef SYS_ACCEPT4
	#define	__NR_accept4	SYS_ACCEPT4
#endif
	#define	__NR_getsockname	SYS_GETSOCKNAME 
	#define	__NR_getpeername	SYS_GETPEERNAME
	#define	__NR_socketpair	SYS_SOCKETPAIR
	#define	__NR_send	SYS_SEND
	#define	__NR_recv	SYS_RECV
	#define	__NR_sendto	SYS_SENDTO
	#define	__NR_recvfrom	SYS_RECVFROM
	#define	__NR_shutdown	SYS_SHUTDOWN
	#define	__NR_setsockopt	SYS_SETSOCKOPT
	#define	__NR_getsockopt	SYS_GETSOCKOPT
	#define	__NR_sendmsg	SYS_SENDMSG
	#define	__NR_recvmsg	SYS_RECVMSG
#endif
	#define __NR_msocket VIRSYS_MSOCKET

#if defined(__powerpc__)
#define AL64 1
#else
#define AL64 0
#endif

/*
 * SYSTEM CALL MAP, columns:
 * num of syscall (unistd.h)
 * choice function
 * wrap_in function
 * wrap out function
 * nested call choice function
 * nested call wrap function
 * flags
 * number of args
 * category of calls 
 *
 * Care should be taken in order to leave the length of this table constant
 * for every architecture, and with the system calls in the same order. If a
 * system call does not appear in one or more architectures it is enough to
 * #define __NR_<systemcallname> __NR_doesnotexist in the corresponding
 * defs_*.h header.
 * */
struct sc_map scmap[]={
	{__NR_doesnotexist, always_null, NULL, NULL,always_null,NULL,0,6,0},

	{__NR_execve,		choice_path,	wrap_in_execve,	wrap_out_execve,always_null,	NULL, ALWAYS,	3, SOC_NONE},
	{__NR_chdir,		choice_path,	wrap_in_chdir,	wrap_out_chdir, always_null,	NULL, ALWAYS,	1, SOC_FILE},
	{__NR_fchdir,		choice_fd,	wrap_in_fchdir,	wrap_out_chdir, always_null,	NULL, ALWAYS,	1, SOC_FILE},
	{__NR_getcwd,		always_null, wrap_in_getcwd,	wrap_out_std,	always_null,	NULL, ALWAYS,	2, SOC_NONE},
	{__NR_open,	choice_path,	wrap_in_open,	wrap_out_open,	nchoice_path,	nw_sysopen, ALWAYS,	3, SOC_FILE},
	{__NR_creat,	choice_path,	wrap_in_open,	wrap_out_open,	nchoice_path,	nw_sysopen, ALWAYS,	2, SOC_FILE},
	{__NR_close,	choice_fd,	wrap_in_close,	wrap_out_close,	nchoice_fd,	nw_sysclose, ALWAYS,	1, SOC_FILE|SOC_NET},
	{__NR_select,	always_null,	wrap_in_select,	wrap_out_select,always_null,	NULL, ALWAYS,	5, SOC_FILE|SOC_NET},
	{__NR_poll,	always_null,	wrap_in_poll,	wrap_out_poll,  always_null,	NULL, ALWAYS,	3, SOC_FILE|SOC_NET},
	{__NR__newselect,always_null,	wrap_in_select,	wrap_out_select,always_null,	NULL, ALWAYS,	5, SOC_FILE|SOC_NET},
	{__NR_pselect6,	always_null,	wrap_in_select,	wrap_out_select,always_null,	NULL, ALWAYS,	6, SOC_FILE|SOC_NET},
	{__NR_ppoll,	always_null,	wrap_in_poll,	wrap_out_poll,  always_null,	NULL, ALWAYS,	4, SOC_FILE|SOC_NET},
	{__NR_umask,	always_null,	wrap_in_umask,  wrap_out_std,	always_null,	NULL, ALWAYS,	1, SOC_FILE|SOC_NET},
	{__NR_chroot,	choice_path,	wrap_in_chroot, wrap_out_chroot,	always_null,	NULL, ALWAYS,	1, SOC_FILE|SOC_NET},
	{__NR_dup,	choice_fd,	wrap_in_dup,	wrap_out_dup,	nchoice_fd, nw_sysdup, ALWAYS,	1, SOC_FILE|SOC_NET},
	{__NR_dup2,	choice_fd,	wrap_in_dup,	wrap_out_dup,	nchoice_fd, nw_sysdup, ALWAYS,	2, SOC_FILE|SOC_NET},
#ifdef __NR_dup3
	{__NR_dup3,	choice_fd,	wrap_in_dup,	wrap_out_dup,	nchoice_fd, nw_sysdup, ALWAYS,	3, SOC_FILE|SOC_NET},
#endif
	{__NR_mount,	choice_mount,	wrap_in_mount,	wrap_out_std,	always_null,	NULL, 0,	5, SOC_FILE},
	{__NR_umount,	choice_path,	wrap_in_umount,	wrap_out_std,	always_null,	NULL, 0,	1, SOC_FILE},
	{__NR_umount2,	choice_path,	wrap_in_umount2,wrap_out_std,	always_null,	NULL, 0,	2, SOC_FILE},
	{__NR_ioctl,	choice_fd,	wrap_in_ioctl,	wrap_out_std, 	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR_read,	choice_fd,	wrap_in_read,	wrap_out_std,	nchoice_fd,	nw_sysfd_std, CB_R,	3, SOC_FILE|SOC_NET},
	{__NR_write,	choice_fd,	wrap_in_write,	wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE|SOC_NET},
	{__NR_readv,	choice_fd,	wrap_in_readv,	wrap_out_std,	nchoice_fd,	nw_sysfd_std, CB_R,	3, SOC_FILE|SOC_NET},
	{__NR_writev,	choice_fd,	wrap_in_writev,	wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE|SOC_NET},
	{__NR_stat,	choice_path,	wrap_in_stat,	wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_lstat,	choice_link,	wrap_in_stat,	wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_fstat,	choice_fd,	wrap_in_fstat,	wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_stat64,	choice_path,	wrap_in_stat64,	wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_lstat64,	choice_link,	wrap_in_stat64,	wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_fstat64,	choice_fd,	wrap_in_fstat64,wrap_out_std,	nchoice_fd,	nw_syspath_std, 0,	2, SOC_FILE|SOC_NET},
	{__NR_chown,	choice_path,	wrap_in_chown, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_lchown,	choice_link,	wrap_in_chown, wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_fchown,	choice_fd,	wrap_in_fchown, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_chown32,	choice_path,	wrap_in_chown, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_lchown32,	choice_link,	wrap_in_chown, wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_fchown32,	choice_fd,	wrap_in_fchown, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE|SOC_UID},
	{__NR_chmod,	choice_path,	wrap_in_chmod, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE},
	{__NR_fchmod,	choice_fd,	wrap_in_fchmod, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	2, SOC_FILE},
	{__NR_getxattr,	choice_path,	wrap_in_getxattr, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	4, SOC_FILE},
	{__NR_lgetxattr,choice_link,	wrap_in_notsupp, wrap_out_std,	nchoice_link,	nw_notsupp, 0,	4, SOC_FILE},
	{__NR_fgetxattr,choice_fd,	wrap_in_notsupp, wrap_out_std,	nchoice_fd,	nw_notsupp, 0,	4, SOC_FILE},
	{__NR_readlink,	choice_link,	wrap_in_readlink,wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	3, SOC_FILE},
	{__NR_getdents,	choice_fd,	wrap_in_getdents,wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR_getdents64,choice_fd,	wrap_in_getdents64,wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR_access,	choice_path,	wrap_in_access, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE},
	{__NR_fcntl,	choice_fd,	wrap_in_fcntl, wrap_out_fcntl,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR_fcntl64,	choice_fd,	wrap_in_fcntl, wrap_out_fcntl,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR_lseek,	choice_fd,	wrap_in_lseek, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	3, SOC_FILE},
	{__NR__llseek,	choice_fd,	wrap_in_llseek, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	5, SOC_FILE},
	{__NR_mkdir,	choice_link,	wrap_in_mkdir, wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	2, SOC_FILE},
	{__NR_rmdir,	choice_path,	wrap_in_unlink, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	1, SOC_FILE},
	{__NR_link,	choice_link2,	wrap_in_link, wrap_out_std,	nchoice_link2,	nw_syslink, 0,	2, SOC_FILE},
	{__NR_symlink,	choice_link2,	wrap_in_symlink, wrap_out_std,	nchoice_link2,	nw_syssymlink, 0,	2, SOC_FILE},
	{__NR_rename,	choice_link2,	wrap_in_link, wrap_out_std,	nchoice_link2,	nw_syslink, 0,	2, SOC_FILE},
	{__NR_unlink,	choice_link,	wrap_in_unlink, wrap_out_std,	nchoice_link,	nw_syspath_std, 0,	1, SOC_FILE},
	{__NR_statfs,	choice_path,	wrap_in_statfs, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE},
	{__NR_fstatfs,	choice_fd,	wrap_in_fstatfs, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	2, SOC_FILE},
	{__NR_statfs64,	choice_path,	wrap_in_statfs64, wrap_out_std,	nchoice_path,	nw_sysstatfs64, 0,	3, SOC_FILE},
	{__NR_fstatfs64,choice_fd,	wrap_in_fstat64, wrap_out_std,	nchoice_fd,	nw_sysfstatfs64, 0,	3, SOC_FILE},
	{__NR_utime,	choice_path,	wrap_in_utime, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE|SOC_TIME},
	{__NR_utimes,	choice_path,	wrap_in_utime, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE|SOC_TIME},
	{__NR_fsync,	choice_fd,	wrap_in_fsync, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	1, SOC_FILE},
	{__NR_fdatasync,choice_fd,	wrap_in_fsync, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	1, SOC_FILE},
	{__NR_truncate,	choice_path,	wrap_in_truncate, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	2, SOC_FILE},
	{__NR_ftruncate,choice_fd,	wrap_in_ftruncate, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	2, SOC_FILE},
	{__NR_truncate64,choice_path,	wrap_in_truncate, wrap_out_std,	nchoice_path,	nw_syspath_std, 0,	AL64+3, SOC_FILE},
	{__NR_ftruncate64,choice_fd,	wrap_in_ftruncate, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	AL64+3, SOC_FILE},
#ifdef __NR_pread64
	{__NR_pread64,	choice_fd,	wrap_in_pread, 	wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	AL64+5, SOC_FILE},
#else
	{__NR_pread,	choice_fd,	wrap_in_pread, 	wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	4, SOC_FILE},
#endif
#ifdef __NR_pwrite64
	{__NR_pwrite64,	choice_fd,	wrap_in_pwrite, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	AL64+5, SOC_FILE},
#else
	{__NR_pwrite,	choice_fd,	wrap_in_pwrite, wrap_out_std,	nchoice_fd,	nw_sysfd_std, 0,	4, SOC_FILE},
#endif
	{__NR_mknod, choice_link, wrap_in_mknod, wrap_out_std, nchoice_path, nw_syspath_std, 0, 3, SOC_FILE},
#ifdef __NR_openat
	{__NR_openat, choice_pathat, wrap_in_open, wrap_out_open, nchoice_pathat, nw_sysopen, ALWAYS, 4, SOC_FILE},
	{__NR_mkdirat, choice_linkat, wrap_in_mkdir, wrap_out_std, nchoice_linkat, nw_sysatpath_std, 0, 3, SOC_FILE},
	{__NR_mknodat, choice_linkat, wrap_in_mknod, wrap_out_std, nchoice_linkat, nw_sysatpath_std, 0, 4, SOC_FILE},
	{__NR_fchownat, choice_pl5at, wrap_in_chown, wrap_out_std, nchoice_pl5at, nw_sysatpath_std, 0, 5, SOC_FILE},
	{__NR_futimesat, choice_pathat, wrap_in_utime, wrap_out_std, nchoice_pathat, nw_sysatpath_std, 0, 3, SOC_FILE},
#ifdef __NR_newfstatat
	/* 64 bit */
	{__NR_newfstatat, choice_pl4at, wrap_in_stat64, wrap_out_std, nchoice_pl4at, nw_sysatpath_std, 0, 4, SOC_FILE},
#else
	{__NR_fstatat64, choice_pl4at, wrap_in_stat64, wrap_out_std, nchoice_pl4at, nw_sysatpath_std, 0, 4, SOC_FILE},
#endif
	{__NR_unlinkat, choice_unlinkat, wrap_in_unlink, wrap_out_std, nchoice_unlinkat, nw_sysatpath_std, 0, 3, SOC_FILE},
	{__NR_renameat, choice_link3at, wrap_in_link, wrap_out_std, nchoice_link3at, nw_syslink, 0, 4, SOC_FILE},
	{__NR_linkat, choice_link3at, wrap_in_link, wrap_out_std, nchoice_link3at, nw_syslink, 0, 4, SOC_FILE},
	{__NR_symlinkat, choice_link2at, wrap_in_symlink, wrap_out_std, nchoice_link2at, nw_syssymlink, 0, 3, SOC_FILE},
	{__NR_readlinkat, choice_linkat, wrap_in_readlink, wrap_out_std, nchoice_linkat, nw_sysatpath_std, 0, 4, SOC_FILE},
	{__NR_fchmodat, choice_pl4at, wrap_in_chmod, wrap_out_std, nchoice_pl4at, nw_sysatpath_std, 0, 4, SOC_FILE},
	{__NR_faccessat, choice_pl4at, wrap_in_access, wrap_out_std, nchoice_pl4at, nw_sysatpath_std, 0, 4, SOC_FILE},
#ifdef __NR_utimensat
	{__NR_utimensat, choice_pl4at, wrap_in_utime,  wrap_out_std, nchoice_pl4at, nw_sysatpath_std, 0, 4, SOC_FILE},
#endif
#endif

#ifdef _UM_MMAP
	/* MMAP management */
	{__NR_mmap,	choice_mmap,	wrap_in_mmap, wrap_out_mmap,	always_null,	NULL, 0,	6, SOC_MMAP},
	{__NR_mmap2,	choice_mmap,	wrap_in_mmap, wrap_out_mmap,	always_null,	NULL, 0,	6, SOC_MMAP},
	{__NR_munmap,	always_null,	wrap_in_munmap, wrap_out_munmap,always_null,	NULL, ALWAYS,	2, SOC_MMAP},
	{__NR_mremap,	always_null,	wrap_in_mremap, wrap_out_mremap,always_null,	NULL, ALWAYS,	4, SOC_MMAP},
#endif

	/* time related calls */
	{__NR_time,	choice_sc,	wrap_in_time, wrap_out_std,	always_null,	NULL, 0,	1, SOC_TIME},
	{__NR_gettimeofday, choice_sc,	wrap_in_gettimeofday, wrap_out_std,	always_null,	NULL, 0,	2, SOC_TIME},
	{__NR_settimeofday, choice_sc,	wrap_in_settimeofday, wrap_out_std,	always_null,	NULL, 0,	2, SOC_TIME},
	{__NR_adjtimex, choice_sc,	wrap_in_adjtimex, wrap_out_std,	always_null,	NULL, 0,	1, SOC_TIME},
	{__NR_clock_gettime, choice_sc,	wrap_in_clock_gettime, wrap_out_std,	always_null,	NULL, 0,	2, SOC_TIME},
	{__NR_clock_settime, choice_sc,	wrap_in_clock_settime, wrap_out_std,	always_null,	NULL, 0,	2, SOC_TIME},
	{__NR_clock_getres, choice_sc,	wrap_in_clock_getres, wrap_out_std,	always_null,	NULL, 0,	2, SOC_TIME},

	/* host id */
	{__NR_oldolduname,	choice_sc,	wrap_in_uname,  wrap_out_std,	always_null,	NULL, 0,	1, SOC_HOSTID},
	{__NR_olduname,	choice_sc,	wrap_in_uname,  wrap_out_std,	always_null,	NULL, 0,	1, SOC_HOSTID},
	{__NR_uname,	choice_sc,	wrap_in_uname,  wrap_out_std,	always_null,	NULL, 0,	1, SOC_HOSTID},
	{__NR_gethostname, choice_sc,	wrap_in_gethostname,  wrap_out_std,	always_null,	NULL, 0,	2, SOC_HOSTID},
	{__NR_sethostname, choice_sc,	wrap_in_sethostname,  wrap_out_std,	always_null,	NULL, 0,	2, SOC_HOSTID},
	{__NR_getdomainname, choice_sc,	wrap_in_gethostname,  wrap_out_std,	always_null,	NULL, 0,	2, SOC_HOSTID},
	{__NR_setdomainname, choice_sc,	wrap_in_sethostname,  wrap_out_std,	always_null,	NULL, 0,	2, SOC_HOSTID},

	/* user mgmt calls */
	{__NR_getuid,	choice_sc,	wrap_in_getxid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setuid,	choice_sc,	wrap_in_setuid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_geteuid,	choice_sc,	wrap_in_getxid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setfsuid,	choice_sc,	wrap_in_setuid, wrap_out_std, 	always_null,	NULL, 0,	1, SOC_UID},
	{__NR_setreuid,	choice_sc,	wrap_in_setreuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	2, SOC_UID},
	{__NR_getresuid, choice_sc,	wrap_in_getresuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_setresuid, choice_sc,	wrap_in_setresuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_getgid,	choice_sc,	wrap_in_getxid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setgid,	choice_sc,	wrap_in_setgid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_getegid,	choice_sc,	wrap_in_getxid16, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setfsgid,	choice_sc,	wrap_in_setgid16, wrap_out_std, 	always_null,	NULL, 0,	1, SOC_UID},
	{__NR_setregid,	choice_sc,	wrap_in_setregid, wrap_out_std, 	always_null,	NULL, ALWAYS,	2, SOC_UID},
	{__NR_getresgid, choice_sc,	wrap_in_getresgid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_setresgid, choice_sc,	wrap_in_setresgid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_getuid32,	choice_sc,	wrap_in_getxid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setuid32,	choice_sc,	wrap_in_setuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_geteuid32,	choice_sc,	wrap_in_getxid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setfsuid32,	choice_sc,	wrap_in_setuid, wrap_out_std, 	always_null,	NULL, 0,	1, SOC_UID},
	{__NR_setreuid32,	choice_sc,	wrap_in_setreuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	2, SOC_UID},
	{__NR_getresuid32, choice_sc,	wrap_in_getresuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_setresuid32, choice_sc,	wrap_in_setresuid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_getgid32,	choice_sc,	wrap_in_getxid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setgid32,	choice_sc,	wrap_in_setgid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_getegid32,	choice_sc,	wrap_in_getxid, wrap_out_std, 	always_null,	NULL, ALWAYS,	1, SOC_UID},
	{__NR_setfsgid32,	choice_sc,	wrap_in_setgid, wrap_out_std, 	always_null,	NULL, 0,	1, SOC_UID},
	{__NR_setregid32,	choice_sc,	wrap_in_setregid, wrap_out_std, 	always_null,	NULL, ALWAYS,	2, SOC_UID},
	{__NR_getresgid32, choice_sc,	wrap_in_getresgid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	{__NR_setresgid32, choice_sc,	wrap_in_setresgid, wrap_out_std, 	always_null,	NULL, ALWAYS,	3, SOC_UID},
	  
	/* priority related calls */
	{__NR_nice,	choice_sc,	wrap_in_nice,  wrap_out_std,	always_null,	NULL, 0,	1, SOC_PRIO},
	{__NR_getpriority, choice_sc,	wrap_in_getpriority, wrap_out_std, always_null,	NULL, 0,	2, SOC_PRIO},
	{__NR_setpriority, choice_sc,	wrap_in_setpriority, wrap_out_std, always_null,	NULL, 0,	3, SOC_PRIO},

	/* process id related */
	{__NR_getpid,	choice_sc,	wrap_in_getpid,  wrap_out_std,	always_null,	NULL, 0,	0, SOC_PID},
	{__NR_getppid,	choice_sc,	wrap_in_getpid,  wrap_out_std,	always_null,	NULL, 0,	0, SOC_PID},
	{__NR_getpgrp,	choice_sc,	wrap_in_getpgrp,  wrap_out_std,	always_null,	NULL, 0,	0, SOC_PID},
	{__NR_setpgrp,	choice_sc,	wrap_in_setpgrp,  wrap_out_std,	always_null,	NULL, 0,	0, SOC_PID},
	{__NR_getpgid,	choice_sc,	wrap_in_getpid_1, wrap_out_std,	always_null,	NULL, 0,	1, SOC_PID},
	{__NR_setpgid,	choice_sc,	wrap_in_setpgid, wrap_out_std,	always_null,	NULL, 0,	2, SOC_PID},
	{__NR_getsid,	choice_sc,	wrap_in_getpid_1, wrap_out_std,	always_null,	NULL, 0,	1, SOC_PID},
	{__NR_setsid,	choice_sc,	wrap_in_setpid,  wrap_out_std,	always_null,	NULL, 0,	0, SOC_PID},

#if 0
	{__NR_sysctl, choice_sysctl, wrap_in_sysctl, wrap_out_sysctl, always_null,	NULL, 0, 2, 0}
	/* this is a trip */
	{__NR_ptrace, always_null, wrap_in_ptrace, wrap_out_ptrace, always_null,	NULL, 0, 4, 0}
#endif

	/* signal management for unblocking processes */
	{__NR_kill,	always_null,	wrap_in_kill, wrap_out_kill, always_null,	NULL, ALWAYS,	4, SOC_SIGNAL},

/* When socketcall does not exist it means that all the socket system calls
 * are normal syscall, thus the tables must be merged together */
#if (__NR_socketcall != __NR_doesnotexist)
};

struct sc_map sockmap[]={
/* 0*/	{__NR_doesnotexist,     always_null,          NULL,                   NULL,   always_null,  NULL, 0,        0, SOC_NET},
#endif
/* 1*/	{__NR_socket,    choice_socket, 	wrap_in_socket,		wrap_out_socket,nchoice_socket,	nw_socket, 0,	3, SOC_SOCKET|SOC_NET}, 
/* 2*/	{__NR_bind,      choice_fd,	wrap_in_bind_connect,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	3, SOC_SOCKET|SOC_NET},
/* 3*/	{__NR_connect,   choice_fd,	wrap_in_bind_connect,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	3, SOC_SOCKET|SOC_NET},
/* 4*/	{__NR_listen,    choice_fd,	wrap_in_listen,		wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	2, SOC_SOCKET|SOC_NET},
/* 5*/	{__NR_accept,    choice_fd,	wrap_in_accept,		wrap_out_socket,nchoice_sfd,	nw_accept,	CB_R,	3, SOC_SOCKET|SOC_NET},
/* 6*/	{__NR_getsockname,choice_fd,	wrap_in_getsock,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	3, SOC_SOCKET|SOC_NET},
/* 7*/	{__NR_getpeername,choice_fd,	wrap_in_getsock,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	3, SOC_SOCKET|SOC_NET},
/* 8*/	{__NR_socketpair,always_null,		NULL, 			NULL,	always_null,	NULL, 0,	4, SOC_SOCKET|SOC_NET}, /* not used */
/* 9*/	{__NR_send,      choice_fd,	wrap_in_send,		wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	4, SOC_SOCKET|SOC_NET},
/*10*/	{__NR_recv,      choice_fd,	wrap_in_recv,		wrap_out_std,	nchoice_sfd,	nw_sockfd_std, CB_R,	4, SOC_SOCKET|SOC_NET},
/*11*/	{__NR_sendto,    choice_fd,	wrap_in_sendto,		wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	6, SOC_SOCKET|SOC_NET},
/*12*/	{__NR_recvfrom,  choice_fd,	wrap_in_recvfrom,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, CB_R,	6, SOC_SOCKET|SOC_NET},
/*13*/	{__NR_shutdown,  choice_fd,	wrap_in_shutdown,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	2, SOC_SOCKET|SOC_NET},
/*14*/	{__NR_setsockopt,choice_fd,	wrap_in_setsockopt,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	5, SOC_SOCKET|SOC_NET},
/*15*/	{__NR_getsockopt,choice_fd,	wrap_in_getsockopt,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	5, SOC_SOCKET|SOC_NET},
/*16*/	{__NR_sendmsg,   choice_fd,	wrap_in_sendmsg,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, 0,	3, SOC_SOCKET|SOC_NET},
/*17*/	{__NR_recvmsg,   choice_fd,	wrap_in_recvmsg,	wrap_out_std,	nchoice_sfd,	nw_sockfd_std, CB_R,	3, SOC_SOCKET|SOC_NET},
#ifdef __NR_accept4
/*18*/	{__NR_accept4,   choice_fd,	wrap_in_accept,	wrap_out_socket,	nchoice_sfd,	nw_accept, CB_R,	4, SOC_SOCKET|SOC_NET},
#endif
};

/* fake sockmap when socket system calls are normal syscalls */
#if (__NR_socketcall == __NR_doesnotexist)
struct sc_map sockmap[]={
	{__NR_doesnotexist,     always_null,          NULL,                   NULL,   always_null,  NULL, 0,        0, SOC_NET},
};
#endif

/* virtual system calls, emulated on sysctl with name==NULL,
 * nlen is the number of call
 * oldval, oldlenp unused
 * newval is the args array
 * newlen is the number of arguments (NOT bytes, number of "long" args)
 * when name != NULL the entry 0 is used thus sysctl could be virtualized */
struct sc_map virscmap[]={
	{__NR_doesnotexist,     always_null,          NULL,                   NULL,   always_null,  NULL, 0,        0, 0},
	{VIRSYS_UMSERVICE,	always_null, wrap_in_umservice, wrap_out_umservice,   always_null,  NULL, ALWAYS, 1, SOC_NONE},
	{VIRSYS_MSOCKET, choice_sockpath, 	wrap_in_msocket,		wrap_out_socket,nchoice_sockpath,	nw_msocket, ALWAYS|NALWAYS,	4, SOC_SOCKET|SOC_NET}, 
};

#define SIZESCMAP (sizeof(scmap)/sizeof(struct sc_map))

#define SIZESOCKMAP (sizeof(sockmap)/sizeof(struct sc_map))

#define SIZEVIRSCMAP (sizeof(virscmap)/sizeof(struct sc_map))

/* unistd syscall number -> scmap table index conversion */
static short scremap[_UM_NR_syscalls];

void init_scmap()
{
	register int i;

	/* initialize the scremap table */
	for (i=0; i<SIZESCMAP; i++) {
		int scno=scmap[i].scno;
		if (scno>=0)
			scremap[scno]=i;
	}
	/* these global variables can be read from (dynamically loaded)
	 * modules */
	scmap_scmapsize = SIZESCMAP;
	scmap_sockmapsize = SIZESOCKMAP;
	scmap_virscmapsize = SIZEVIRSCMAP;
}

/* unistd number to scmap index remap, 0 if non-existent */
int uscno(int scno)
{
	if (scno >= 0 && scno < _UM_NR_syscalls)
		return scremap[scno];
	else
		return 0;
}

// vim: ts=8
