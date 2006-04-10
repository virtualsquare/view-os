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
//#include <sys/socket.h>
typedef int (*intfun)();
typedef unsigned char service_t;

#define CHECKNOCHECK	0
#define CHECKPATH 		1
#define CHECKSOCKET 	2
#define CHECKFSTYPE 	3
#define CHECKSC 5
// for IOCTL mgmt
#define CHECKIOCTLPARMS   0x40000000
#define IOCTLLENMASK      0x07ffffff
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
struct ioctl_len_req {
	int fd;
	int req;
};

//
#define FLAG_WANTREGISTER	0x80000000

struct service {
	char *name;
	service_t code;

	/* handle to service data. It is used by um_service.c to store
	 * dynamic lib handle (see dlopen (3))*/
	void *dlhandle;

	/*addproc is called when a new process is created
	 * (int id, int max, void *umph)
	 * max is the current max number of processes: service implementation can use it
	 * to realloc their internal structures. ID is an internal id, *not*
	 * the pid! id is in the range 0,...,max-1 it is never reassigned during
	 * the life of a process, can be used as an index for internal data*/
	intfun addproc;

	/*delproc is called when a process terminates.
	 * (int id, void *umph)
	 * is the garbage collection function for the data that addproc may have created
	 */
	intfun delproc;

	/* choice function: returns TRUE if this path must be managed by this module
	 * FALSE otherwise.
	 * checkfun functions has the following args:
	 *  (int type, void *arg) or
	 *  (int type, void *arg, void *umph)
	 *  type is defined by CHECK... constants above
	 */
	intfun checkfun;

	/* proactive management of select/poll system call. The module provides this function
	 * to activate a callback when an event occurs.
	 * it has the followin args:
	 * (void (* cb)(), void *arg, int fd, int how)    (plus umph if needed)
	 * cb: the callback function (if NULL, it means that a previous registration for callback
	 *     must be deleted).
	 * arg: argument passed to the callback function
	 * fd: fd (i.e. sfd, the fd as seen by the service module)
	 * how: 0x1 READ_OK, 0x2 WRITE_OK, 0x4 EXTRA
	 */
	intfun select_register;

	/* the syscall table, the arguments are the same of the "real world" syscalls,
	 * plus umph if needed*/
	intfun *syscall;

	/* the socket call table, the arguments are the same of the "real world" syscalls,
	 * plus umph if needed*/
	intfun *socket;
};

extern int _lwip_version;
extern int scmap_scmapsize;
extern int scmap_sockmapsize;

extern int um_mod_getpid(void *umph);
extern int um_mod_umoven(void *umph, long addr, int len, void *_laddr);
extern int um_mod_umovestr(void *umph, long addr, int len, void *_laddr);
extern int um_mod_ustoren(void *umph, long addr, int len, void *_laddr);
extern int um_mod_ustorestr(void *umph, long addr, int len, void *_laddr);
extern int um_mod_getsyscallno(void *umph);
extern int um_mod_getumpid(void *umph);
extern long* um_mod_getargs(void *umph);
extern struct stat64 *um_mod_getpathstat(void *umph);
extern int um_mod_getsyscalltype(int scno);

extern int uscno(int scno);
extern int add_service(struct service *);

#ifdef NEW_SERVICE_LIST
extern int gas_register_service(struct service *);
extern int gas_deregister_service(int);
#endif

#define __NR_doesnotexist -1
#if defined(__x86_64__)
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
#endif
