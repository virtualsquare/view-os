/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
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
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */   
/*
 * Neelkanth Natu (neelnatu@yahoo.com) is the author of this file.
 * As long as you keep this blurb in the file, feel free to do whatever.
 */ 
#ifndef NATIVE_SYSCALLS_H
#define NATIVE_SYSCALLS_H

extern int native_socket(int domain, int type, int protocol);
extern int native_connect(int sockfd, const void *servaddr,
			  socklen_t addrlen);
extern int native_bind(int sockfd, 
		       void *my_addr, socklen_t addrlen);
extern int native_accept(int sockfd, 
		         void *my_addr, socklen_t *addrlen);
extern int native_listen(int s, int backlog);
extern int native_getsockname(int s, void *name, socklen_t *namelen);
extern int native_getpeername(int s, void *name, socklen_t *namelen);
extern int native_select(int nfds, fd_set *rdset, fd_set *wrset, fd_set *xpset,
			 struct timeval *timeout);
extern int native_read(int fd, void *buf, size_t count);
extern ssize_t native_write(int fd, const void *buf, size_t count);
extern int native_open(const char *pathname, int flags);
extern int native_close(int fd);
extern int native_ioctl(int fd, unsigned long int command, char *data);
extern int native_setsockopt(int fd, int level, int optname, 
			     void *optval, socklen_t optlen);
extern int native_getsockopt(int fd, int level, int optname, 
			     void *optval, socklen_t *optlen);

extern ssize_t native_send(int s, const void *msg, size_t len, int flags);
extern int native_sendto(int s, const void *msg, size_t len, int flags,
			 void *to, socklen_t tolen);
extern int native_sendmsg(int s, const void *msg, int flags);

extern int native_recv(int s, void *buf, size_t len, int flags);
extern int native_recvfrom(int s, void *buf, size_t len, int flags,
		 	   void *from, socklen_t *fromlen);
extern int native_recvmsg(int s, void *msg, int flags);
extern int native_shutdown(int s, int how);
extern int native_fcntl(int fd, int cmd, long arg);
extern pid_t native_fork(void);
extern int native_dup2(int old_fd, int new_fd);
extern int native_dup(int old_fd);
extern off_t native_lseek(int fd, off_t offset, int whence);
extern ssize_t native_sendfile(int out_fd, int in_fd, off_t *offset, size_t n);

#endif	/* ifndef NATIVE_SYSCALLS_H */
