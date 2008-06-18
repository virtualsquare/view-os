/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   fill_request.h: header of the fill RSC request functions used by tests 
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

#ifndef __FILL_REQUEST_HEADER__
#define __FILL_REQUEST_HEADER__
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <string.h>

#include "rsc_client.h"

#define FALSE 0
#define TRUE  1


struct sockaddr_in *fill_struct_sockaddr_in(void);
char *fill_string(char *str);

/**********************************************************/
/* Fill request                                           */
/**********************************************************/
struct _llseek_req *fill__llseek_request(void);
struct accept_req *fill_accept_request(int addrlen_null);
struct access_req *fill_access_request(int pathname_null);
struct adjtimex_req *fill_adjtimex_request(int buf_null);
struct bind_req *fill_bind_request(int my_addr_null);
struct chdir_req *fill_chdir_request(int path_null);
struct chmod_req *fill_chmod_request(int path_null);
struct chown_req *fill_chown_request(int path_null);
struct chown32_req *fill_chown32_request(int path_null);
struct clock_getres_req *fill_clock_getres_request(void);
struct clock_gettime_req *fill_clock_gettime_request(void);
struct clock_settime_req *fill_clock_settime_request(int tp_null);
struct close_req *fill_close_request(void);
struct connect_req *fill_connect_request(int serv_addr_null);
struct dup_req *fill_dup_request(void);
struct dup2_req *fill_dup2_request(void);
struct fchdir_req *fill_fchdir_request(void);
struct fchmod_req *fill_fchmod_request(void);
struct fchown_req *fill_fchown_request(void);
struct fchown32_req *fill_fchown32_request(void);
struct fdatasync_req *fill_fdatasync_request(void);
struct fgetxattr_req *fill_fgetxattr_request(int name_null);
struct fstat64_req *fill_fstat64_request(void);
struct fstatfs64_req *fill_fstatfs64_request(void);
struct fsync_req *fill_fsync_request(void);
struct ftruncate64_req *fill_ftruncate64_request(void);
struct getdents64_req *fill_getdents64_request(void);
struct getpeername_req *fill_getpeername_request(int namelen_null);
struct getsockname_req *fill_getsockname_request(int namelen_null);
struct getsockopt_req *fill_getsockopt_request(int optlen_null);
struct gettimeofday_req *fill_gettimeofday_request(void);
struct getxattr_req *fill_getxattr_request(int path_null, int name_null);
struct lchown_req *fill_lchown_request(int path_null);
struct lchown32_req *fill_lchown32_request(int path_null);
struct lgetxattr_req *fill_lgetxattr_request(int path_null, int name_null);
struct link_req *fill_link_request(int oldpath_null, int newpath_null);
struct listen_req *fill_listen_request(void);
struct lseek_req *fill_lseek_request(void);
struct lstat64_req *fill_lstat64_request(int path_null);
struct mkdir_req *fill_mkdir_request(int pathname_null);
struct mount_req *fill_mount_request(int source_null, int target_null, int filesystemtype_null, int data_null);
struct open_req *fill_open_request(int pathname_null);
struct pread64_req *fill_pread64_request(void);
struct pwrite64_req *fill_pwrite64_request(int buf_null);
struct read_req *fill_read_request(void);
struct readlink_req *fill_readlink_request(int path_null);
struct recv_req *fill_recv_request(void);
struct recvfrom_req *fill_recvfrom_request(int fromlen_null, int from_null);
struct rename_req *fill_rename_request(int oldpath_null, int newpath_null);
struct rmdir_req *fill_rmdir_request(int pathname_null);
struct send_req *fill_send_request(int buf_null);
struct sendto_req *fill_sendto_request(int buf_null, int to_null);
struct setdomainname_req *fill_setdomainname_request(int name_null);
struct sethostname_req *fill_sethostname_request(int name_null);
struct setsockopt_req *fill_setsockopt_request(int optval_null);
struct settimeofday_req *fill_settimeofday_request(int tv_null, int tz_null);
struct shutdown_req *fill_shutdown_request(void);
struct socket_req *fill_socket_request(void);
struct stat64_req *fill_stat64_request(int path_null);
struct statfs64_req *fill_statfs64_request(int path_null);
struct symlink_req *fill_symlink_request(int oldpath_null, int newpath_null);
struct truncate64_req *fill_truncate64_request(int path_null);
struct umount2_req *fill_umount2_request(int target_null);
struct uname_req *fill_uname_request(void);
struct unlink_req *fill_unlink_request(int pathname_null);
struct utime_req *fill_utime_request(int filename_null, int buf_null);
struct utimes_req *fill_utimes_request(int filename_null);
struct write_req *fill_write_request(int buf_null);

#define FILL_IOCTL_R    0x1  
#define FILL_IOCTL_W    0x2
#define FILL_IOCTL_RW   (FILL_IOCTL_R | FILL_IOCTL_W)
struct ioctl_req *fill_ioctl_request(int arg_null, int how);
struct fcntl_req *fill_fcntl_request(u_int16_t cmd_type, int lock_null);
/**********************************************************/
/* Free filled request                                    */
/**********************************************************/
void free_filled__llseek_request(struct _llseek_req *req, int only_pointed_memory);
void free_filled_accept_request(struct accept_req *req, int only_pointed_memory);
void free_filled_access_request(struct access_req *req, int only_pointed_memory);
void free_filled_adjtimex_request(struct adjtimex_req *req, int only_pointed_memory);
void free_filled_bind_request(struct bind_req *req, int only_pointed_memory);
void free_filled_chdir_request(struct chdir_req *req, int only_pointed_memory);
void free_filled_chmod_request(struct chmod_req *req, int only_pointed_memory);
void free_filled_chown_request(struct chown_req *req, int only_pointed_memory);
void free_filled_chown32_request(struct chown32_req *req, int only_pointed_memory);
void free_filled_clock_getres_request(struct clock_getres_req *req, int only_pointed_memory);
void free_filled_clock_gettime_request(struct clock_gettime_req *req, int only_pointed_memory);
void free_filled_clock_settime_request(struct clock_settime_req *req, int only_pointed_memory);
void free_filled_close_request(struct close_req *req, int only_pointed_memory);
void free_filled_connect_request(struct connect_req *req, int only_pointed_memory);
void free_filled_dup_request(struct dup_req *req, int only_pointed_memory);
void free_filled_dup2_request(struct dup2_req *req, int only_pointed_memory);
void free_filled_fchdir_request(struct fchdir_req *req, int only_pointed_memory);
void free_filled_fchmod_request(struct fchmod_req *req, int only_pointed_memory);
void free_filled_fchown_request(struct fchown_req *req, int only_pointed_memory);
void free_filled_fchown32_request(struct fchown32_req *req, int only_pointed_memory);
void free_filled_fdatasync_request(struct fdatasync_req *req, int only_pointed_memory);
void free_filled_fgetxattr_request(struct fgetxattr_req *req, int only_pointed_memory);
void free_filled_fstat64_request(struct fstat64_req *req, int only_pointed_memory);
void free_filled_fstatfs64_request(struct fstatfs64_req *req, int only_pointed_memory);
void free_filled_fsync_request(struct fsync_req *req, int only_pointed_memory);
void free_filled_ftruncate64_request(struct ftruncate64_req *req, int only_pointed_memory);
void free_filled_getdents64_request(struct getdents64_req *req, int only_pointed_memory);
void free_filled_getpeername_request(struct getpeername_req *req, int only_pointed_memory);
void free_filled_getsockname_request(struct getsockname_req *req, int only_pointed_memory);
void free_filled_getsockopt_request(struct getsockopt_req *req, int only_pointed_memory);
void free_filled_gettimeofday_request(struct gettimeofday_req *req, int only_pointed_memory);
void free_filled_getxattr_request(struct getxattr_req *req, int only_pointed_memory);
void free_filled_lchown_request(struct lchown_req *req, int only_pointed_memory);
void free_filled_lchown32_request(struct lchown32_req *req, int only_pointed_memory);
void free_filled_lgetxattr_request(struct lgetxattr_req *req, int only_pointed_memory);
void free_filled_link_request(struct link_req *req, int only_pointed_memory);
void free_filled_listen_request(struct listen_req *req, int only_pointed_memory);
void free_filled_lseek_request(struct lseek_req *req, int only_pointed_memory);
void free_filled_lstat64_request(struct lstat64_req *req, int only_pointed_memory);
void free_filled_mkdir_request(struct mkdir_req *req, int only_pointed_memory);
void free_filled_mount_request(struct mount_req *req, int only_pointed_memory);
void free_filled_open_request(struct open_req *req, int only_pointed_memory);
void free_filled_pread64_request(struct pread64_req *req, int only_pointed_memory);
void free_filled_pwrite64_request(struct pwrite64_req *req, int only_pointed_memory);
void free_filled_read_request(struct read_req *req, int only_pointed_memory);
void free_filled_readlink_request(struct readlink_req *req, int only_pointed_memory);
void free_filled_recv_request(struct recv_req *req, int only_pointed_memory);
void free_filled_recvfrom_request(struct recvfrom_req *req, int only_pointed_memory);
void free_filled_rename_request(struct rename_req *req, int only_pointed_memory);
void free_filled_rmdir_request(struct rmdir_req *req, int only_pointed_memory);
void free_filled_send_request(struct send_req *req, int only_pointed_memory);
void free_filled_sendto_request(struct sendto_req *req, int only_pointed_memory);
void free_filled_setdomainname_request(struct setdomainname_req *req, int only_pointed_memory);
void free_filled_sethostname_request(struct sethostname_req *req, int only_pointed_memory);
void free_filled_setsockopt_request(struct setsockopt_req *req, int only_pointed_memory);
void free_filled_settimeofday_request(struct settimeofday_req *req, int only_pointed_memory);
void free_filled_shutdown_request(struct shutdown_req *req, int only_pointed_memory);
void free_filled_socket_request(struct socket_req *req, int only_pointed_memory);
void free_filled_stat64_request(struct stat64_req *req, int only_pointed_memory);
void free_filled_statfs64_request(struct statfs64_req *req, int only_pointed_memory);
void free_filled_symlink_request(struct symlink_req *req, int only_pointed_memory);
void free_filled_truncate64_request(struct truncate64_req *req, int only_pointed_memory);
void free_filled_umount2_request(struct umount2_req *req, int only_pointed_memory);
void free_filled_uname_request(struct uname_req *req, int only_pointed_memory);
void free_filled_unlink_request(struct unlink_req *req, int only_pointed_memory);
void free_filled_utime_request(struct utime_req *req, int only_pointed_memory);
void free_filled_utimes_request(struct utimes_req *req, int only_pointed_memory);
void free_filled_write_request(struct write_req *req, int only_pointed_memory);
void free_filled_fcntl_request(struct fcntl_req *req, int only_pointed_memory);
void free_filled_ioctl_request(struct ioctl_req *req, int only_pointed_memory);
#endif /* __FILL_REQUEST_HEADER__ */
