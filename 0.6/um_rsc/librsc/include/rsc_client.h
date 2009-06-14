/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   rsc_client.h: client side functions header
 *   
 *   Copyright (C) 2007 Andrea Forni
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
 */
#ifndef __RSC_CLIENT_HEADER__
#define __RSC_CLIENT_HEADER__

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include "aconv.h"
#include "rsc_messages.h"
#include "rsc_consts.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
/*************************************************/
/*   CALLBACK REGISTRATION STRUCTURES            */
/*************************************************/
struct reg_cbs {
  struct reg_cb *v;
  int size;
  int nentry;
};

struct reg_cb {
  int fd;
  int how;
  void (* cb)();
  void *arg;
  /* Added to patch the event subscribe loop problem */
  int ack; /* Is the value of the ACK received. It's initialized to -1  */
  int cb_executed; /* True if the callback has been already executed, false otherwise */
};


/*************************************************/
/*   INIT FUNCTION                               */
/*************************************************/
int rscc_init(int client_fd, int event_sub_fd, struct reg_cbs **rc, enum arch c_arch, enum arch s_arch);


/*************************************************/
/*   EVENT SUBSCRIPTION                          */
/*************************************************/
int rscc_es_send_req(struct reg_cbs *reg_cbs, int server_fd, int event_sub_fd, int how, void (* cb)(), void *arg);


/*************************************************/
/*   INTERFACE 1: rscc functions                 */
/*************************************************/

int rscc__llseek(unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence);
int rscc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int rscc_access(char *pathname, int mode);
int rscc_adjtimex(struct timex *buf);
int rscc_bind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
int rscc_chdir(char *path);
int rscc_chmod(char *path, mode_t mode);
int rscc_chown(char *path, uid_t owner, gid_t group);
int rscc_chown32(char *path, uid_t owner, gid_t group);
int rscc_clock_getres(clockid_t clk_id, struct timespec *res);
int rscc_clock_gettime(clockid_t clk_id, struct timespec *tp);
int rscc_clock_settime(clockid_t clk_id, struct timespec *tp);
int rscc_close(int fd);
int rscc_connect(int sockfd, struct sockaddr *serv_addr, socklen_t addrlen);
int rscc_dup(int oldfd);
int rscc_dup2(int oldfd, int newfd);
int rscc_fchdir(int fd);
int rscc_fchmod(int fildes, mode_t mode);
int rscc_fchown(int fd, uid_t owner, gid_t group);
int rscc_fchown32(int fd, uid_t owner, gid_t group);
int rscc_fdatasync(int fd);
int rscc_fgetxattr(int filedes, char *name, void *value, size_t size);
int rscc_fstat64(int filedes, struct stat64 *buf);
int rscc_fstatfs64(unsigned int fd, struct statfs64 *buf);
int rscc_fsync(int fd);
int rscc_ftruncate64(int fd, __off64_t length);
int rscc_getdents64(unsigned int fd, struct dirent64 *dirp, unsigned int count);
int rscc_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
int rscc_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
int rscc_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
int rscc_gettimeofday(struct timeval *tv, struct timezone *tz);
int rscc_getxattr(char *path, char *name, void *value, size_t size);
int rscc_lchown(char *path, uid_t owner, gid_t group);
int rscc_lchown32(char *path, uid_t owner, gid_t group);
int rscc_lgetxattr(char *path, char *name, void *value, size_t size);
int rscc_link(char *oldpath, char *newpath);
int rscc_listen(int sockfd, int backlog);
int rscc_lseek(int fildes, off_t offset, int whence);
int rscc_lstat64(char *path, struct stat64 *buf);
int rscc_mkdir(char *pathname, mode_t mode);
int rscc_mount(char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data);
int rscc_open(char *pathname, int flags);
int rscc_pread64(int fd, void *buf, size_t count, off_t offset);
int rscc_pwrite64(int fd, void *buf, size_t count, off_t offset);
int rscc_read(int fd, void *buf, size_t count);
int rscc_readlink(char *path, char *buf, size_t bufsiz);
int rscc_recv(int s, void *buf, size_t len, int flags);
int rscc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int rscc_rename(char *oldpath, char *newpath);
int rscc_rmdir(char *pathname);
int rscc_send(int s, void *buf, size_t len, int flags);
int rscc_sendto(int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen);
int rscc_setdomainname(char *name, size_t len);
int rscc_sethostname(char *name, size_t len);
int rscc_setsockopt(int s, int level, int optname, void *optval, socklen_t optlen);
int rscc_settimeofday(struct timeval *tv, struct timezone *tz);
int rscc_shutdown(int s, int how);
int rscc_socket(int domain, int type, int protocol);
int rscc_stat64(char *path, struct stat64 *buf);
int rscc_statfs64(char *path, struct statfs64 *buf);
int rscc_symlink(char *oldpath, char *newpath);
int rscc_truncate64(char *path, __off64_t length);
int rscc_umount2(char *target, int flags);
int rscc_uname(struct utsname *buf);
int rscc_unlink(char *pathname);
int rscc_utime(char *filename, struct utimbuf *buf);
int rscc_utimes(char *filename, struct timeval tv[2]);
int rscc_write(int fd, void *buf, size_t count);
int rscc_ioctl(int d, int request, void *arg);
int rscc_fcntl(int fd, int cmd, ...);

/*************************************************************/
/*   INTERFACE 2: create_request/manage_response functions   */
/*************************************************************/
struct iovec *rscc_create__llseek_request(int *total_size, int *iovec_count, unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence);
struct iovec *rscc_manage__llseek_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, unsigned long int offset_high, unsigned long int offset_low, loff_t *result, unsigned int whence);
struct iovec *rscc_create_accept_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
struct iovec *rscc_manage_accept_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
struct iovec *rscc_create_access_request(int *total_size, int *iovec_count, char *pathname, int mode);
struct iovec *rscc_manage_access_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, int mode);
struct iovec *rscc_create_adjtimex_request(int *total_size, int *iovec_count, struct timex *buf);
struct iovec *rscc_manage_adjtimex_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timex *buf);
struct iovec *rscc_create_bind_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
struct iovec *rscc_manage_bind_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
struct iovec *rscc_create_chdir_request(int *total_size, int *iovec_count, char *path);
struct iovec *rscc_manage_chdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path);
struct iovec *rscc_create_chmod_request(int *total_size, int *iovec_count, char *path, mode_t mode);
struct iovec *rscc_manage_chmod_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, mode_t mode);
struct iovec *rscc_create_chown_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group);
struct iovec *rscc_manage_chown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group);
struct iovec *rscc_create_chown32_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group);
struct iovec *rscc_manage_chown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group);
struct iovec *rscc_create_clock_getres_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *res);
struct iovec *rscc_manage_clock_getres_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *res);
struct iovec *rscc_create_clock_gettime_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *tp);
struct iovec *rscc_manage_clock_gettime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *tp);
struct iovec *rscc_create_clock_settime_request(int *total_size, int *iovec_count, clockid_t clk_id, struct timespec *tp);
struct iovec *rscc_manage_clock_settime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, clockid_t clk_id, struct timespec *tp);
struct iovec *rscc_create_close_request(int *total_size, int *iovec_count, int fd);
struct iovec *rscc_manage_close_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd);
struct iovec *rscc_create_connect_request(int *total_size, int *iovec_count, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen);
struct iovec *rscc_manage_connect_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen);
struct iovec *rscc_create_dup_request(int *total_size, int *iovec_count, int oldfd);
struct iovec *rscc_manage_dup_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int oldfd);
struct iovec *rscc_create_dup2_request(int *total_size, int *iovec_count, int oldfd, int newfd);
struct iovec *rscc_manage_dup2_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int oldfd, int newfd);
struct iovec *rscc_create_fchdir_request(int *total_size, int *iovec_count, int fd);
struct iovec *rscc_manage_fchdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd);
struct iovec *rscc_create_fchmod_request(int *total_size, int *iovec_count, int fildes, mode_t mode);
struct iovec *rscc_manage_fchmod_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fildes, mode_t mode);
struct iovec *rscc_create_fchown_request(int *total_size, int *iovec_count, int fd, uid_t owner, gid_t group);
struct iovec *rscc_manage_fchown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, uid_t owner, gid_t group);
struct iovec *rscc_create_fchown32_request(int *total_size, int *iovec_count, int fd, uid_t owner, gid_t group);
struct iovec *rscc_manage_fchown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, uid_t owner, gid_t group);
struct iovec *rscc_create_fdatasync_request(int *total_size, int *iovec_count, int fd);
struct iovec *rscc_manage_fdatasync_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd);
struct iovec *rscc_create_fgetxattr_request(int *total_size, int *iovec_count, int filedes, char *name, void *value, size_t size);
struct iovec *rscc_manage_fgetxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int filedes, char *name, void *value, size_t size);
struct iovec *rscc_create_fstat64_request(int *total_size, int *iovec_count, int filedes, struct stat64 *buf);
struct iovec *rscc_manage_fstat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int filedes, struct stat64 *buf);
struct iovec *rscc_create_fstatfs64_request(int *total_size, int *iovec_count, unsigned int fd, struct statfs64 *buf);
struct iovec *rscc_manage_fstatfs64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, struct statfs64 *buf);
struct iovec *rscc_create_fsync_request(int *total_size, int *iovec_count, int fd);
struct iovec *rscc_manage_fsync_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd);
struct iovec *rscc_create_ftruncate64_request(int *total_size, int *iovec_count, int fd, __off64_t length);
struct iovec *rscc_manage_ftruncate64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, __off64_t length);
struct iovec *rscc_create_getdents64_request(int *total_size, int *iovec_count, unsigned int fd, struct dirent64 *dirp, unsigned int count);
struct iovec *rscc_manage_getdents64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, unsigned int fd, struct dirent64 *dirp, unsigned int count);
struct iovec *rscc_create_getpeername_request(int *total_size, int *iovec_count, int s, struct sockaddr *name, socklen_t *namelen);
struct iovec *rscc_manage_getpeername_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, struct sockaddr *name, socklen_t *namelen);
struct iovec *rscc_create_getsockname_request(int *total_size, int *iovec_count, int s, struct sockaddr *name, socklen_t *namelen);
struct iovec *rscc_manage_getsockname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, struct sockaddr *name, socklen_t *namelen);
struct iovec *rscc_create_getsockopt_request(int *total_size, int *iovec_count, int s, int level, int optname, void *optval, socklen_t *optlen);
struct iovec *rscc_manage_getsockopt_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int level, int optname, void *optval, socklen_t *optlen);
struct iovec *rscc_create_gettimeofday_request(int *total_size, int *iovec_count, struct timeval *tv, struct timezone *tz);
struct iovec *rscc_manage_gettimeofday_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timeval *tv, struct timezone *tz);
struct iovec *rscc_create_getxattr_request(int *total_size, int *iovec_count, char *path, char *name, void *value, size_t size);
struct iovec *rscc_manage_getxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *name, void *value, size_t size);
struct iovec *rscc_create_lchown_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group);
struct iovec *rscc_manage_lchown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group);
struct iovec *rscc_create_lchown32_request(int *total_size, int *iovec_count, char *path, uid_t owner, gid_t group);
struct iovec *rscc_manage_lchown32_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, uid_t owner, gid_t group);
struct iovec *rscc_create_lgetxattr_request(int *total_size, int *iovec_count, char *path, char *name, void *value, size_t size);
struct iovec *rscc_manage_lgetxattr_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *name, void *value, size_t size);
struct iovec *rscc_create_link_request(int *total_size, int *iovec_count, char *oldpath, char *newpath);
struct iovec *rscc_manage_link_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath);
struct iovec *rscc_create_listen_request(int *total_size, int *iovec_count, int sockfd, int backlog);
struct iovec *rscc_manage_listen_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int sockfd, int backlog);
struct iovec *rscc_create_lseek_request(int *total_size, int *iovec_count, int fildes, off_t offset, int whence);
struct iovec *rscc_manage_lseek_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fildes, off_t offset, int whence);
struct iovec *rscc_create_lstat64_request(int *total_size, int *iovec_count, char *path, struct stat64 *buf);
struct iovec *rscc_manage_lstat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct stat64 *buf);
struct iovec *rscc_create_mkdir_request(int *total_size, int *iovec_count, char *pathname, mode_t mode);
struct iovec *rscc_manage_mkdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, mode_t mode);
struct iovec *rscc_create_mount_request(int *total_size, int *iovec_count, char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data);
struct iovec *rscc_manage_mount_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *source, char *target, char *filesystemtype, unsigned long int mountflags, void *data);
struct iovec *rscc_create_open_request(int *total_size, int *iovec_count, char *pathname, int flags);
struct iovec *rscc_manage_open_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname, int flags);
struct iovec *rscc_create_pread64_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count, off_t offset);
struct iovec *rscc_manage_pread64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count, off_t offset);
struct iovec *rscc_create_pwrite64_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count, off_t offset);
struct iovec *rscc_manage_pwrite64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count, off_t offset);
struct iovec *rscc_create_read_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count);
struct iovec *rscc_manage_read_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count);
struct iovec *rscc_create_readlink_request(int *total_size, int *iovec_count, char *path, char *buf, size_t bufsiz);
struct iovec *rscc_manage_readlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, char *buf, size_t bufsiz);
struct iovec *rscc_create_recv_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags);
struct iovec *rscc_manage_recv_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags);
struct iovec *rscc_create_recvfrom_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
struct iovec *rscc_manage_recvfrom_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
struct iovec *rscc_create_rename_request(int *total_size, int *iovec_count, char *oldpath, char *newpath);
struct iovec *rscc_manage_rename_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath);
struct iovec *rscc_create_rmdir_request(int *total_size, int *iovec_count, char *pathname);
struct iovec *rscc_manage_rmdir_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname);
struct iovec *rscc_create_send_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags);
struct iovec *rscc_manage_send_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags);
struct iovec *rscc_create_sendto_request(int *total_size, int *iovec_count, int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen);
struct iovec *rscc_manage_sendto_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, void *buf, size_t len, int flags, struct sockaddr *to, socklen_t tolen);
struct iovec *rscc_create_setdomainname_request(int *total_size, int *iovec_count, char *name, size_t len);
struct iovec *rscc_manage_setdomainname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *name, size_t len);
struct iovec *rscc_create_sethostname_request(int *total_size, int *iovec_count, char *name, size_t len);
struct iovec *rscc_manage_sethostname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *name, size_t len);
struct iovec *rscc_create_setsockopt_request(int *total_size, int *iovec_count, int s, int level, int optname, void *optval, socklen_t optlen);
struct iovec *rscc_manage_setsockopt_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int level, int optname, void *optval, socklen_t optlen);
struct iovec *rscc_create_settimeofday_request(int *total_size, int *iovec_count, struct timeval *tv, struct timezone *tz);
struct iovec *rscc_manage_settimeofday_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct timeval *tv, struct timezone *tz);
struct iovec *rscc_create_shutdown_request(int *total_size, int *iovec_count, int s, int how);
struct iovec *rscc_manage_shutdown_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int s, int how);
struct iovec *rscc_create_socket_request(int *total_size, int *iovec_count, int domain, int type, int protocol);
struct iovec *rscc_manage_socket_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int domain, int type, int protocol);
struct iovec *rscc_create_stat64_request(int *total_size, int *iovec_count, char *path, struct stat64 *buf);
struct iovec *rscc_manage_stat64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct stat64 *buf);
struct iovec *rscc_create_statfs64_request(int *total_size, int *iovec_count, char *path, struct statfs64 *buf);
struct iovec *rscc_manage_statfs64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, struct statfs64 *buf);
struct iovec *rscc_create_symlink_request(int *total_size, int *iovec_count, char *oldpath, char *newpath);
struct iovec *rscc_manage_symlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *oldpath, char *newpath);
struct iovec *rscc_create_truncate64_request(int *total_size, int *iovec_count, char *path, __off64_t length);
struct iovec *rscc_manage_truncate64_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *path, __off64_t length);
struct iovec *rscc_create_umount2_request(int *total_size, int *iovec_count, char *target, int flags);
struct iovec *rscc_manage_umount2_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *target, int flags);
struct iovec *rscc_create_uname_request(int *total_size, int *iovec_count, struct utsname *buf);
struct iovec *rscc_manage_uname_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, struct utsname *buf);
struct iovec *rscc_create_unlink_request(int *total_size, int *iovec_count, char *pathname);
struct iovec *rscc_manage_unlink_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *pathname);
struct iovec *rscc_create_utime_request(int *total_size, int *iovec_count, char *filename, struct utimbuf *buf);
struct iovec *rscc_manage_utime_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *filename, struct utimbuf *buf);
struct iovec *rscc_create_utimes_request(int *total_size, int *iovec_count, char *filename, struct timeval tv[2]);
struct iovec *rscc_manage_utimes_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, char *filename, struct timeval tv[2]);
struct iovec *rscc_create_write_request(int *total_size, int *iovec_count, int fd, void *buf, size_t count);
struct iovec *rscc_manage_write_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, int fd, void *buf, size_t count);
struct iovec *rscc_create_fcntl_request(int *total_size, int *iovec_count, u_int16_t cmd_type, int fd, int cmd, long third_arg);
struct iovec *rscc_manage_fcntl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int16_t cmd_type, long third_arg);

u_int32_t rscc_check_ioctl_request(int request);
struct iovec *rscc_create_ioctl_request(int *total_size, int *iovec_count, u_int32_t size_type, int d, int request, void *arg);
struct iovec *rscc_manage_ioctl_response(struct sys_resp_header *resp_header, int *iovec_count, int *nbytes, u_int32_t size_type, void *arg);
#endif /* __RSC_CLIENT_HEADER__ */
