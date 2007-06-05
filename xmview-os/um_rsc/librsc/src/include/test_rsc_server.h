/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   test_rsc_server.h: header containing private server side functions to be tested
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
#ifndef __RSC_SERVER_TESTS_H__
#define __RSC_SERVER_TESTS_H__


#ifdef RSCDEBUG
#include "rsc_messages.h"
struct ioctl_resp_header *rscs_manage_ioctl_request(struct ioctl_req_header *ioctl_req);

void accept_adjust_read_pointers(struct accept_req *accept_req);
void access_adjust_read_pointers(struct access_req *access_req);
void adjtimex_adjust_read_pointers(struct adjtimex_req *adjtimex_req);
void bind_adjust_read_pointers(struct bind_req *bind_req);
void chdir_adjust_read_pointers(struct chdir_req *chdir_req);
void chmod_adjust_read_pointers(struct chmod_req *chmod_req);
void chown_adjust_read_pointers(struct chown_req *chown_req);
void chown32_adjust_read_pointers(struct chown32_req *chown32_req);
void clock_settime_adjust_read_pointers(struct clock_settime_req *clock_settime_req);
void connect_adjust_read_pointers(struct connect_req *connect_req);
void fgetxattr_adjust_read_pointers(struct fgetxattr_req *fgetxattr_req);
void getpeername_adjust_read_pointers(struct getpeername_req *getpeername_req);
void getsockname_adjust_read_pointers(struct getsockname_req *getsockname_req);
void getsockopt_adjust_read_pointers(struct getsockopt_req *getsockopt_req);
void getxattr_adjust_read_pointers(struct getxattr_req *getxattr_req);
void lchown_adjust_read_pointers(struct lchown_req *lchown_req);
void lchown32_adjust_read_pointers(struct lchown32_req *lchown32_req);
void lgetxattr_adjust_read_pointers(struct lgetxattr_req *lgetxattr_req);
void link_adjust_read_pointers(struct link_req *link_req);
void lstat64_adjust_read_pointers(struct lstat64_req *lstat64_req);
void mkdir_adjust_read_pointers(struct mkdir_req *mkdir_req);
void mount_adjust_read_pointers(struct mount_req *mount_req);
void open_adjust_read_pointers(struct open_req *open_req);
void pwrite64_adjust_read_pointers(struct pwrite64_req *pwrite64_req);
void readlink_adjust_read_pointers(struct readlink_req *readlink_req);
void recvfrom_adjust_read_pointers(struct recvfrom_req *recvfrom_req);
void rename_adjust_read_pointers(struct rename_req *rename_req);
void rmdir_adjust_read_pointers(struct rmdir_req *rmdir_req);
void send_adjust_read_pointers(struct send_req *send_req);
void sendto_adjust_read_pointers(struct sendto_req *sendto_req);
void setdomainname_adjust_read_pointers(struct setdomainname_req *setdomainname_req);
void sethostname_adjust_read_pointers(struct sethostname_req *sethostname_req);
void setsockopt_adjust_read_pointers(struct setsockopt_req *setsockopt_req);
void settimeofday_adjust_read_pointers(struct settimeofday_req *settimeofday_req);
void stat64_adjust_read_pointers(struct stat64_req *stat64_req);
void statfs64_adjust_read_pointers(struct statfs64_req *statfs64_req);
void symlink_adjust_read_pointers(struct symlink_req *symlink_req);
void truncate64_adjust_read_pointers(struct truncate64_req *truncate64_req);
void umount2_adjust_read_pointers(struct umount2_req *umount2_req);
void unlink_adjust_read_pointers(struct unlink_req *unlink_req);
void utime_adjust_read_pointers(struct utime_req *utime_req);
void utimes_adjust_read_pointers(struct utimes_req *utimes_req);
void write_adjust_read_pointers(struct write_req *write_req);

void _llseek_adjust_write_pointers(struct _llseek_req *_llseek_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void accept_adjust_write_pointers(struct accept_req *accept_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void adjtimex_adjust_write_pointers(struct adjtimex_req *adjtimex_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void clock_getres_adjust_write_pointers(struct clock_getres_req *clock_getres_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void clock_gettime_adjust_write_pointers(struct clock_gettime_req *clock_gettime_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void fgetxattr_adjust_write_pointers(struct fgetxattr_req *fgetxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void fstat64_adjust_write_pointers(struct fstat64_req *fstat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void fstatfs64_adjust_write_pointers(struct fstatfs64_req *fstatfs64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void getdents64_adjust_write_pointers(struct getdents64_req *getdents64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void getpeername_adjust_write_pointers(struct getpeername_req *getpeername_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void getsockname_adjust_write_pointers(struct getsockname_req *getsockname_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void getsockopt_adjust_write_pointers(struct getsockopt_req *getsockopt_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void gettimeofday_adjust_write_pointers(struct gettimeofday_req *gettimeofday_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void getxattr_adjust_write_pointers(struct getxattr_req *getxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void lgetxattr_adjust_write_pointers(struct lgetxattr_req *lgetxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void lstat64_adjust_write_pointers(struct lstat64_req *lstat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void pread64_adjust_write_pointers(struct pread64_req *pread64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void read_adjust_write_pointers(struct read_req *read_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void readlink_adjust_write_pointers(struct readlink_req *readlink_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void recv_adjust_write_pointers(struct recv_req *recv_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void recvfrom_adjust_write_pointers(struct recvfrom_req *recvfrom_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void stat64_adjust_write_pointers(struct stat64_req *stat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void statfs64_adjust_write_pointers(struct statfs64_req *statfs64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
void uname_adjust_write_pointers(struct uname_req *uname_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch);
struct sys_resp_header *rscs_pre__llseek_exec(void *req, enum arch client_arch);
int rscs_exec__llseek(void  *request);
struct sys_resp_header *rscs_post__llseek_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_accept_exec(void *req, enum arch client_arch);
int rscs_exec_accept(void  *request);
struct sys_resp_header *rscs_post_accept_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_access_exec(void *req, enum arch client_arch);
int rscs_exec_access(void  *request);
struct sys_resp_header *rscs_post_access_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_adjtimex_exec(void *req, enum arch client_arch);
int rscs_exec_adjtimex(void  *request);
struct sys_resp_header *rscs_post_adjtimex_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_bind_exec(void *req, enum arch client_arch);
int rscs_exec_bind(void  *request);
struct sys_resp_header *rscs_post_bind_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_chdir_exec(void *req, enum arch client_arch);
int rscs_exec_chdir(void  *request);
struct sys_resp_header *rscs_post_chdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_chmod_exec(void *req, enum arch client_arch);
int rscs_exec_chmod(void  *request);
struct sys_resp_header *rscs_post_chmod_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_chown_exec(void *req, enum arch client_arch);
int rscs_exec_chown(void  *request);
struct sys_resp_header *rscs_post_chown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_chown32_exec(void *req, enum arch client_arch);
int rscs_exec_chown32(void  *request);
struct sys_resp_header *rscs_post_chown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_clock_getres_exec(void *req, enum arch client_arch);
int rscs_exec_clock_getres(void  *request);
struct sys_resp_header *rscs_post_clock_getres_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_clock_gettime_exec(void *req, enum arch client_arch);
int rscs_exec_clock_gettime(void  *request);
struct sys_resp_header *rscs_post_clock_gettime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_clock_settime_exec(void *req, enum arch client_arch);
int rscs_exec_clock_settime(void  *request);
struct sys_resp_header *rscs_post_clock_settime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_close_exec(void *req, enum arch client_arch);
int rscs_exec_close(void  *request);
struct sys_resp_header *rscs_post_close_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_connect_exec(void *req, enum arch client_arch);
int rscs_exec_connect(void  *request);
struct sys_resp_header *rscs_post_connect_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_dup_exec(void *req, enum arch client_arch);
int rscs_exec_dup(void  *request);
struct sys_resp_header *rscs_post_dup_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_dup2_exec(void *req, enum arch client_arch);
int rscs_exec_dup2(void  *request);
struct sys_resp_header *rscs_post_dup2_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fchdir_exec(void *req, enum arch client_arch);
int rscs_exec_fchdir(void  *request);
struct sys_resp_header *rscs_post_fchdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fchmod_exec(void *req, enum arch client_arch);
int rscs_exec_fchmod(void  *request);
struct sys_resp_header *rscs_post_fchmod_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fchown_exec(void *req, enum arch client_arch);
int rscs_exec_fchown(void  *request);
struct sys_resp_header *rscs_post_fchown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fchown32_exec(void *req, enum arch client_arch);
int rscs_exec_fchown32(void  *request);
struct sys_resp_header *rscs_post_fchown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fdatasync_exec(void *req, enum arch client_arch);
int rscs_exec_fdatasync(void  *request);
struct sys_resp_header *rscs_post_fdatasync_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fgetxattr_exec(void *req, enum arch client_arch);
int rscs_exec_fgetxattr(void  *request);
struct sys_resp_header *rscs_post_fgetxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fstat64_exec(void *req, enum arch client_arch);
int rscs_exec_fstat64(void  *request);
struct sys_resp_header *rscs_post_fstat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fstatfs64_exec(void *req, enum arch client_arch);
int rscs_exec_fstatfs64(void  *request);
struct sys_resp_header *rscs_post_fstatfs64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fsync_exec(void *req, enum arch client_arch);
int rscs_exec_fsync(void  *request);
struct sys_resp_header *rscs_post_fsync_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_ftruncate64_exec(void *req, enum arch client_arch);
int rscs_exec_ftruncate64(void  *request);
struct sys_resp_header *rscs_post_ftruncate64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_getdents64_exec(void *req, enum arch client_arch);
int rscs_exec_getdents64(void  *request);
struct sys_resp_header *rscs_post_getdents64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_getpeername_exec(void *req, enum arch client_arch);
int rscs_exec_getpeername(void  *request);
struct sys_resp_header *rscs_post_getpeername_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_getsockname_exec(void *req, enum arch client_arch);
int rscs_exec_getsockname(void  *request);
struct sys_resp_header *rscs_post_getsockname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_getsockopt_exec(void *req, enum arch client_arch);
int rscs_exec_getsockopt(void  *request);
struct sys_resp_header *rscs_post_getsockopt_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_gettimeofday_exec(void *req, enum arch client_arch);
int rscs_exec_gettimeofday(void  *request);
struct sys_resp_header *rscs_post_gettimeofday_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_getxattr_exec(void *req, enum arch client_arch);
int rscs_exec_getxattr(void  *request);
struct sys_resp_header *rscs_post_getxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_lchown_exec(void *req, enum arch client_arch);
int rscs_exec_lchown(void  *request);
struct sys_resp_header *rscs_post_lchown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_lchown32_exec(void *req, enum arch client_arch);
int rscs_exec_lchown32(void  *request);
struct sys_resp_header *rscs_post_lchown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_lgetxattr_exec(void *req, enum arch client_arch);
int rscs_exec_lgetxattr(void  *request);
struct sys_resp_header *rscs_post_lgetxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_link_exec(void *req, enum arch client_arch);
int rscs_exec_link(void  *request);
struct sys_resp_header *rscs_post_link_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_listen_exec(void *req, enum arch client_arch);
int rscs_exec_listen(void  *request);
struct sys_resp_header *rscs_post_listen_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_lseek_exec(void *req, enum arch client_arch);
int rscs_exec_lseek(void  *request);
struct sys_resp_header *rscs_post_lseek_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_lstat64_exec(void *req, enum arch client_arch);
int rscs_exec_lstat64(void  *request);
struct sys_resp_header *rscs_post_lstat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_mkdir_exec(void *req, enum arch client_arch);
int rscs_exec_mkdir(void  *request);
struct sys_resp_header *rscs_post_mkdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_mount_exec(void *req, enum arch client_arch);
int rscs_exec_mount(void  *request);
struct sys_resp_header *rscs_post_mount_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_open_exec(void *req, enum arch client_arch);
int rscs_exec_open(void  *request);
struct sys_resp_header *rscs_post_open_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_pread64_exec(void *req, enum arch client_arch);
int rscs_exec_pread64(void  *request);
struct sys_resp_header *rscs_post_pread64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_pwrite64_exec(void *req, enum arch client_arch);
int rscs_exec_pwrite64(void  *request);
struct sys_resp_header *rscs_post_pwrite64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_read_exec(void *req, enum arch client_arch);
int rscs_exec_read(void  *request);
struct sys_resp_header *rscs_post_read_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_readlink_exec(void *req, enum arch client_arch);
int rscs_exec_readlink(void  *request);
struct sys_resp_header *rscs_post_readlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_recv_exec(void *req, enum arch client_arch);
int rscs_exec_recv(void  *request);
struct sys_resp_header *rscs_post_recv_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_recvfrom_exec(void *req, enum arch client_arch);
int rscs_exec_recvfrom(void  *request);
struct sys_resp_header *rscs_post_recvfrom_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_rename_exec(void *req, enum arch client_arch);
int rscs_exec_rename(void  *request);
struct sys_resp_header *rscs_post_rename_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_rmdir_exec(void *req, enum arch client_arch);
int rscs_exec_rmdir(void  *request);
struct sys_resp_header *rscs_post_rmdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_send_exec(void *req, enum arch client_arch);
int rscs_exec_send(void  *request);
struct sys_resp_header *rscs_post_send_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_sendto_exec(void *req, enum arch client_arch);
int rscs_exec_sendto(void  *request);
struct sys_resp_header *rscs_post_sendto_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_setdomainname_exec(void *req, enum arch client_arch);
int rscs_exec_setdomainname(void  *request);
struct sys_resp_header *rscs_post_setdomainname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_sethostname_exec(void *req, enum arch client_arch);
int rscs_exec_sethostname(void  *request);
struct sys_resp_header *rscs_post_sethostname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_setsockopt_exec(void *req, enum arch client_arch);
int rscs_exec_setsockopt(void  *request);
struct sys_resp_header *rscs_post_setsockopt_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_settimeofday_exec(void *req, enum arch client_arch);
int rscs_exec_settimeofday(void  *request);
struct sys_resp_header *rscs_post_settimeofday_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_shutdown_exec(void *req, enum arch client_arch);
int rscs_exec_shutdown(void  *request);
struct sys_resp_header *rscs_post_shutdown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_socket_exec(void *req, enum arch client_arch);
int rscs_exec_socket(void  *request);
struct sys_resp_header *rscs_post_socket_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_stat64_exec(void *req, enum arch client_arch);
int rscs_exec_stat64(void  *request);
struct sys_resp_header *rscs_post_stat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_statfs64_exec(void *req, enum arch client_arch);
int rscs_exec_statfs64(void  *request);
struct sys_resp_header *rscs_post_statfs64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_symlink_exec(void *req, enum arch client_arch);
int rscs_exec_symlink(void  *request);
struct sys_resp_header *rscs_post_symlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_truncate64_exec(void *req, enum arch client_arch);
int rscs_exec_truncate64(void  *request);
struct sys_resp_header *rscs_post_truncate64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_umount2_exec(void *req, enum arch client_arch);
int rscs_exec_umount2(void  *request);
struct sys_resp_header *rscs_post_umount2_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_uname_exec(void *req, enum arch client_arch);
int rscs_exec_uname(void  *request);
struct sys_resp_header *rscs_post_uname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_unlink_exec(void *req, enum arch client_arch);
int rscs_exec_unlink(void  *request);
struct sys_resp_header *rscs_post_unlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_utime_exec(void *req, enum arch client_arch);
int rscs_exec_utime(void  *request);
struct sys_resp_header *rscs_post_utime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_utimes_exec(void *req, enum arch client_arch);
int rscs_exec_utimes(void  *request);
struct sys_resp_header *rscs_post_utimes_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_write_exec(void *req, enum arch client_arch);
int rscs_exec_write(void  *request);
struct sys_resp_header *rscs_post_write_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
#endif /* RSCDEBUG */
#endif /* __RSC_SERVER_TESTS_H__ */
