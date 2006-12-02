/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   
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
#include <sys/syscall.h>
#include <unistd.h>
#include <stdarg.h>
//#include <sys/socket.h>

extern int _umview_version;

typedef long (*sysfun)();
typedef long long epoch_t;
struct treepoch;
struct timestamp {
	epoch_t epoch;
	struct treepoch *treepoch;
};

extern epoch_t tst_matchingepoch(struct timestamp *service_tst);
extern struct timestamp tst_timestamp();
extern epoch_t get_epoch();

extern epoch_t um_setepoch(epoch_t epoch);

typedef epoch_t (*epochfun)();
typedef unsigned char service_t;

#define CHECKNOCHECK	0
#define CHECKPATH 		1
#define CHECKSOCKET 	2
#define CHECKFSTYPE 	3
#define CHECKSC 5
#define CHECKBINFMT 6

// for IOCTL mgmt
#define CHECKIOCTLPARMS   0x40000000
#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
struct ioctl_len_req {
	int fd;
	int req;
};

#define BINFMT_MODULE_ALLOC 1
#define BINFMT_KEEP_ARG0 2
struct binfmt_req {
	char *path;
	char *interp;
	int flags;
};


struct service {
	char *name;
	service_t code;

	/* handle to service data. It is used by um_service.c to store
	 * dynamic lib handle (see dlopen (3))*/
	void *dlhandle;

	/*addproc is called when a new process is created
	 * (int umpid, int pumpid, int numprocs)
	 * numprocs is the current max number of processes: service implementation can use it
	 * to realloc their internal structures. UMPID is an internal id, *not*
	 * the pid! id is in the range 0,...,numprocs-1 it is never reassigned during
	 * the life of a process, can be used as an index for internal data
	 * pumpid is the similar id for the parent process, -1 if it does not exist */
	sysfun addproc;

	/*delproc is called when a process terminates.
	 * (int id)
	 * is the garbage collection function for the data that addproc may have created
	 */
	sysfun delproc;

	/* choice function: returns TRUE if this path must be managed by this module
	 * FALSE otherwise.
	 * Nesting modules: returns the epoch of best match (0 if non found).
	 *
	 * checkfun functions has the following args:
	 *  (int type, void *arg) or
	 *  type is defined by CHECK... constants above
	 */
	epochfun checkfun;

	/* proactive management of select/poll system call. The module provides this function
	 * to activate a callback when an event occurs.
	 * it has the followin args:
	 * (void (* cb)(), void *arg, int fd, int events)    
	 * cb: the callback function (if NULL, it means that a previous registration for callback
	 *     must be deleted).
	 * arg: argument passed to the callback function
	 * fd: fd (i.e. sfd, the fd as seen by the service module)
	 * events: as defined in poll(2)
	 */
	sysfun event_subscribe;

	/* the syscall table, the arguments are the same of the "real world" syscalls,*/
	sysfun *syscall;

	/* the socket call table, the arguments are the same of the "real world" syscalls,*/
	sysfun *socket;
};

extern int _lwip_version;
extern int scmap_scmapsize;
extern int scmap_sockmapsize;

extern int um_mod_getpid(void);
extern int um_mod_umoven(long addr, int len, void *_laddr);
extern int um_mod_umovestr(long addr, int len, void *_laddr);
extern int um_mod_ustoren(long addr, int len, void *_laddr);
extern int um_mod_ustorestr(long addr, int len, void *_laddr);
extern int um_mod_getsyscallno(void);
extern int um_mod_getumpid(void);
extern long* um_mod_getargs(void);
extern struct stat64 *um_mod_getpathstat(void);
char *um_mod_getpath(void);
extern int um_mod_getsyscalltype(int scno);
int um_mod_event_subscribe(void (* cb)(), void *arg, int fd, int how);

extern int uscno(int scno);
extern int add_service(struct service *);

extern int fprint2(const char *fmt, ...);
extern int vfprint2(const char *fmt, va_list ap);

#define __NR_doesnotexist -1
#if defined(__x86_64__)
#define __NR_socketcall __NR_doesnotexist
#define __NR__newselect __NR_doesnotexist
#define __NR_umount __NR_doesnotexist
#define __NR_stat64 __NR_doesnotexist
#define __NR_lstat64 __NR_doesnotexist
#define __NR_fstat64 __NR_doesnotexist
#define __NR_chown32 __NR_doesnotexist
#define __NR_lchown32 __NR_doesnotexist
#define __NR_fchown32 __NR_doesnotexist
#define __NR_fcntl64 __NR_doesnotexist
#define __NR__llseek __NR_doesnotexist
#define __NR_send __NR_doesnotexist
#define __NR_recv __NR_doesnotexist
#endif

#if (__NR_socketcall != __NR_doesnotexist)
#define __NR_socket     SYS_SOCKET
#define __NR_bind       SYS_BIND
#define __NR_connect    SYS_CONNECT
#define __NR_listen     SYS_LISTEN
#define __NR_accept     SYS_ACCEPT
#define __NR_getsockname        SYS_GETSOCKNAME
#define __NR_getpeername        SYS_GETPEERNAME
#define __NR_socketpair SYS_SOCKETPAIR
#define __NR_send       SYS_SEND
#define __NR_recv       SYS_RECV
#define __NR_sendto     SYS_SENDTO
#define __NR_recvfrom   SYS_RECVFROM
#define __NR_shutdown   SYS_SHUTDOWN
#define __NR_setsockopt SYS_SETSOCKOPT
#define __NR_getsockopt SYS_GETSOCKOPT
#define __NR_sendmsg    SYS_SENDMSG
#define __NR_recvmsg    SYS_RECVMSG
#endif

#define INTERNAL_MAKE_NAME(a, b) a ## b
#define MAKE_NAME(a, b) INTERNAL_MAKE_NAME(a, b)

#define SERVICESYSCALL(s, scno, sfun) (s.syscall[uscno(MAKE_NAME(__NR_, scno))] = (sysfun) sfun)
#if (__NR_socketcall == __NR_doesnotexist)
#define SERVICESOCKET(s, scno, sfun) (s.syscall[uscno(MAKE_NAME(__NR_, scno))] = (sysfun) sfun)
#else
#define SERVICESOCKET(s, scno, sfun) (s.socket[MAKE_NAME(__NR_, scno)] = (sysfun) sfun)
#endif
