/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   rsc_server.c: server side functions 
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

#ifndef __USE_LARGEFILE64
#define __USE_LARGEFILE64
#endif

#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "rsc_server.h"
#include "utils.h"
#include "aconv.h"
#include "rsc_consts.h"
#include "generic_list.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>
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
static enum arch my_arch;
static struct list *ioctl_list;
/*########################################################################*/
/*##                                                                    ##*/
/*##  REQUEST FUNCTION DECLARATIONS and HANDLER TABLE                   ##*/
/*##                                                                    ##*/
/*########################################################################*/
typedef struct sys_resp_header *(*rscs_pre_exec)(void *req, enum arch client_arch);
typedef int (*rscs_exec)(void *request);
typedef struct sys_resp_header *(*rscs_post_exec)(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);

/* static void *req_func_recvmsg(void *req); */
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
struct sys_resp_header *rscs_pre_ioctl_exec(void *req, enum arch client_arch);
int rscs_exec_ioctl(void  *request);
struct sys_resp_header *rscs_post_ioctl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);
struct sys_resp_header *rscs_pre_fcntl_exec(void *req, enum arch client_arch);
int rscs_exec_fcntl(void  *request);
struct sys_resp_header *rscs_post_fcntl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch);

/* Handler Tables */
rscs_pre_exec rscs_pre_exec_table[] = {
  /* 0. __RSC__exit */ NULL,
  /* 1. __RSC__llseek */ rscs_pre__llseek_exec,
  /* 2. __RSC__newselect */ NULL,
  /* 3. __RSC__sysctl */ NULL,
  /* 4. __RSC_accept */ rscs_pre_accept_exec,
  /* 5. __RSC_access */ rscs_pre_access_exec,
  /* 6. __RSC_acct */ NULL,
  /* 7. __RSC_add_key */ NULL,
  /* 8. __RSC_adjtimex */ rscs_pre_adjtimex_exec,
  /* 9. __RSC_afs_syscall */ NULL,
  /* 10. __RSC_alarm */ NULL,
  /* 11. __RSC_arch_prctl */ NULL,
  /* 12. __RSC_bdflush */ NULL,
  /* 13. __RSC_bind */ rscs_pre_bind_exec,
  /* 14. __RSC_break */ NULL,
  /* 15. __RSC_brk */ NULL,
  /* 16. __RSC_capget */ NULL,
  /* 17. __RSC_capset */ NULL,
  /* 18. __RSC_chdir */ rscs_pre_chdir_exec,
  /* 19. __RSC_chmod */ rscs_pre_chmod_exec,
  /* 20. __RSC_chown */ rscs_pre_chown_exec,
  /* 21. __RSC_chown32 */ rscs_pre_chown32_exec,
  /* 22. __RSC_chroot */ NULL,
  /* 23. __RSC_clock_getres */ rscs_pre_clock_getres_exec,
  /* 24. __RSC_clock_gettime */ rscs_pre_clock_gettime_exec,
  /* 25. __RSC_clock_nanosleep */ NULL,
  /* 26. __RSC_clock_settime */ rscs_pre_clock_settime_exec,
  /* 27. __RSC_clone */ NULL,
  /* 28. __RSC_close */ rscs_pre_close_exec,
  /* 29. __RSC_connect */ rscs_pre_connect_exec,
  /* 30. __RSC_creat */ NULL,
  /* 31. __RSC_create_module */ NULL,
  /* 32. __RSC_delete_module */ NULL,
  /* 33. __RSC_dup */ rscs_pre_dup_exec,
  /* 34. __RSC_dup2 */ rscs_pre_dup2_exec,
  /* 35. __RSC_epoll_create */ NULL,
  /* 36. __RSC_epoll_ctl */ NULL,
  /* 37. __RSC_epoll_ctl_old */ NULL,
  /* 38. __RSC_epoll_wait */ NULL,
  /* 39. __RSC_epoll_wait_old */ NULL,
  /* 40. __RSC_execve */ NULL,
  /* 41. __RSC_exit */ NULL,
  /* 42. __RSC_exit_group */ NULL,
  /* 43. __RSC_fadvise64 */ NULL,
  /* 44. __RSC_fadvise64_64 */ NULL,
  /* 45. __RSC_fchdir */ rscs_pre_fchdir_exec,
  /* 46. __RSC_fchmod */ rscs_pre_fchmod_exec,
  /* 47. __RSC_fchown */ rscs_pre_fchown_exec,
  /* 48. __RSC_fchown32 */ rscs_pre_fchown32_exec,
  /* 49. __RSC_fcntl */ rscs_pre_fcntl_exec,
  /* 50. __RSC_fcntl64 */ NULL,
  /* 51. __RSC_fdatasync */ rscs_pre_fdatasync_exec,
  /* 52. __RSC_fgetxattr */ rscs_pre_fgetxattr_exec,
  /* 53. __RSC_flistxattr */ NULL,
  /* 54. __RSC_flock */ NULL,
  /* 55. __RSC_fork */ NULL,
  /* 56. __RSC_fremovexattr */ NULL,
  /* 57. __RSC_fsetxattr */ NULL,
  /* 58. __RSC_fstat */ NULL,
  /* 59. __RSC_fstat64 */ rscs_pre_fstat64_exec,
  /* 60. __RSC_fstatfs */ NULL,
  /* 61. __RSC_fstatfs64 */ rscs_pre_fstatfs64_exec,
  /* 62. __RSC_fsync */ rscs_pre_fsync_exec,
  /* 63. __RSC_ftime */ NULL,
  /* 64. __RSC_ftruncate */ NULL,
  /* 65. __RSC_ftruncate64 */ rscs_pre_ftruncate64_exec,
  /* 66. __RSC_futex */ NULL,
  /* 67. __RSC_get_kernel_syms */ NULL,
  /* 68. __RSC_get_mempolicy */ NULL,
  /* 69. __RSC_get_thread_area */ NULL,
  /* 70. __RSC_getcwd */ NULL,
  /* 71. __RSC_getdents */ NULL,
  /* 72. __RSC_getdents64 */ rscs_pre_getdents64_exec,
  /* 73. __RSC_getegid */ NULL,
  /* 74. __RSC_getegid32 */ NULL,
  /* 75. __RSC_geteuid */ NULL,
  /* 76. __RSC_geteuid32 */ NULL,
  /* 77. __RSC_getgid */ NULL,
  /* 78. __RSC_getgid32 */ NULL,
  /* 79. __RSC_getgroups */ NULL,
  /* 80. __RSC_getgroups32 */ NULL,
  /* 81. __RSC_getitimer */ NULL,
  /* 82. __RSC_getpeername */ rscs_pre_getpeername_exec,
  /* 83. __RSC_getpgid */ NULL,
  /* 84. __RSC_getpgrp */ NULL,
  /* 85. __RSC_getpid */ NULL,
  /* 86. __RSC_getpmsg */ NULL,
  /* 87. __RSC_getppid */ NULL,
  /* 88. __RSC_getpriority */ NULL,
  /* 89. __RSC_getresgid */ NULL,
  /* 90. __RSC_getresgid32 */ NULL,
  /* 91. __RSC_getresuid */ NULL,
  /* 92. __RSC_getresuid32 */ NULL,
  /* 93. __RSC_getrlimit */ NULL,
  /* 94. __RSC_getrusage */ NULL,
  /* 95. __RSC_getsid */ NULL,
  /* 96. __RSC_getsockname */ rscs_pre_getsockname_exec,
  /* 97. __RSC_getsockopt */ rscs_pre_getsockopt_exec,
  /* 98. __RSC_gettid */ NULL,
  /* 99. __RSC_gettimeofday */ rscs_pre_gettimeofday_exec,
  /* 100. __RSC_getuid */ NULL,
  /* 101. __RSC_getuid32 */ NULL,
  /* 102. __RSC_getxattr */ rscs_pre_getxattr_exec,
  /* 103. __RSC_gtty */ NULL,
  /* 104. __RSC_idle */ NULL,
  /* 105. __RSC_init_module */ NULL,
  /* 106. __RSC_io_cancel */ NULL,
  /* 107. __RSC_io_destroy */ NULL,
  /* 108. __RSC_io_getevents */ NULL,
  /* 109. __RSC_io_setup */ NULL,
  /* 110. __RSC_io_submit */ NULL,
  /* 111. __RSC_ioctl */ rscs_pre_ioctl_exec,
  /* 112. __RSC_ioperm */ NULL,
  /* 113. __RSC_iopl */ NULL,
  /* 114. __RSC_ipc */ NULL,
  /* 115. __RSC_kexec_load */ NULL,
  /* 116. __RSC_keyctl */ NULL,
  /* 117. __RSC_kill */ NULL,
  /* 118. __RSC_lchown */ rscs_pre_lchown_exec,
  /* 119. __RSC_lchown32 */ rscs_pre_lchown32_exec,
  /* 120. __RSC_lgetxattr */ rscs_pre_lgetxattr_exec,
  /* 121. __RSC_link */ rscs_pre_link_exec,
  /* 122. __RSC_listen */ rscs_pre_listen_exec,
  /* 123. __RSC_listxattr */ NULL,
  /* 124. __RSC_llistxattr */ NULL,
  /* 125. __RSC_lock */ NULL,
  /* 126. __RSC_lookup_dcookie */ NULL,
  /* 127. __RSC_lremovexattr */ NULL,
  /* 128. __RSC_lseek */ rscs_pre_lseek_exec,
  /* 129. __RSC_lsetxattr */ NULL,
  /* 130. __RSC_lstat */ NULL,
  /* 131. __RSC_lstat64 */ rscs_pre_lstat64_exec,
  /* 132. __RSC_madvise */ NULL,
  /* 133. __RSC_madvise1 */ NULL,
  /* 134. __RSC_mbind */ NULL,
  /* 135. __RSC_mincore */ NULL,
  /* 136. __RSC_mkdir */ rscs_pre_mkdir_exec,
  /* 137. __RSC_mknod */ NULL,
  /* 138. __RSC_mlock */ NULL,
  /* 139. __RSC_mlockall */ NULL,
  /* 140. __RSC_mmap */ NULL,
  /* 141. __RSC_mmap2 */ NULL,
  /* 142. __RSC_modify_ldt */ NULL,
  /* 143. __RSC_mount */ rscs_pre_mount_exec,
  /* 144. __RSC_mprotect */ NULL,
  /* 145. __RSC_mpx */ NULL,
  /* 146. __RSC_mq_getsetattr */ NULL,
  /* 147. __RSC_mq_notify */ NULL,
  /* 148. __RSC_mq_open */ NULL,
  /* 149. __RSC_mq_timedreceive */ NULL,
  /* 150. __RSC_mq_timedsend */ NULL,
  /* 151. __RSC_mq_unlink */ NULL,
  /* 152. __RSC_mremap */ NULL,
  /* 153. __RSC_msgctl */ NULL,
  /* 154. __RSC_msgget */ NULL,
  /* 155. __RSC_msgrcv */ NULL,
  /* 156. __RSC_msgsnd */ NULL,
  /* 157. __RSC_msync */ NULL,
  /* 158. __RSC_multiplexer */ NULL,
  /* 159. __RSC_munlock */ NULL,
  /* 160. __RSC_munlockall */ NULL,
  /* 161. __RSC_munmap */ NULL,
  /* 162. __RSC_nanosleep */ NULL,
  /* 163. __RSC_nfsservctl */ NULL,
  /* 164. __RSC_nice */ NULL,
  /* 165. __RSC_oldfstat */ NULL,
  /* 166. __RSC_oldlstat */ NULL,
  /* 167. __RSC_oldolduname */ NULL,
  /* 168. __RSC_oldstat */ NULL,
  /* 169. __RSC_olduname */ NULL,
  /* 170. __RSC_open */ rscs_pre_open_exec,
  /* 171. __RSC_pause */ NULL,
  /* 172. __RSC_pciconfig_iobase */ NULL,
  /* 173. __RSC_pciconfig_read */ NULL,
  /* 174. __RSC_pciconfig_write */ NULL,
  /* 175. __RSC_personality */ NULL,
  /* 176. __RSC_pipe */ NULL,
  /* 177. __RSC_pivot_root */ NULL,
  /* 178. __RSC_poll */ NULL,
  /* 179. __RSC_prctl */ NULL,
  /* 180. __RSC_pread64 */ rscs_pre_pread64_exec,
  /* 181. __RSC_prof */ NULL,
  /* 182. __RSC_profil */ NULL,
  /* 183. __RSC_ptrace */ NULL,
  /* 184. __RSC_putpmsg */ NULL,
  /* 185. __RSC_pwrite64 */ rscs_pre_pwrite64_exec,
  /* 186. __RSC_query_module */ NULL,
  /* 187. __RSC_quotactl */ NULL,
  /* 188. __RSC_read */ rscs_pre_read_exec,
  /* 189. __RSC_readahead */ NULL,
  /* 190. __RSC_readdir */ NULL,
  /* 191. __RSC_readlink */ rscs_pre_readlink_exec,
  /* 192. __RSC_readv */ NULL,
  /* 193. __RSC_reboot */ NULL,
  /* 194. __RSC_recv */ rscs_pre_recv_exec,
  /* 195. __RSC_recvfrom */ rscs_pre_recvfrom_exec,
  /* 196. __RSC_recvmsg */ NULL,
  /* 197. __RSC_remap_file_pages */ NULL,
  /* 198. __RSC_removexattr */ NULL,
  /* 199. __RSC_rename */ rscs_pre_rename_exec,
  /* 200. __RSC_request_key */ NULL,
  /* 201. __RSC_restart_syscall */ NULL,
  /* 202. __RSC_rmdir */ rscs_pre_rmdir_exec,
  /* 203. __RSC_rt_sigaction */ NULL,
  /* 204. __RSC_rt_sigpending */ NULL,
  /* 205. __RSC_rt_sigprocmask */ NULL,
  /* 206. __RSC_rt_sigqueueinfo */ NULL,
  /* 207. __RSC_rt_sigreturn */ NULL,
  /* 208. __RSC_rt_sigsuspend */ NULL,
  /* 209. __RSC_rt_sigtimedwait */ NULL,
  /* 210. __RSC_sched_get_priority_max */ NULL,
  /* 211. __RSC_sched_get_priority_min */ NULL,
  /* 212. __RSC_sched_getaffinity */ NULL,
  /* 213. __RSC_sched_getparam */ NULL,
  /* 214. __RSC_sched_getscheduler */ NULL,
  /* 215. __RSC_sched_rr_get_interval */ NULL,
  /* 216. __RSC_sched_setaffinity */ NULL,
  /* 217. __RSC_sched_setparam */ NULL,
  /* 218. __RSC_sched_setscheduler */ NULL,
  /* 219. __RSC_sched_yield */ NULL,
  /* 220. __RSC_security */ NULL,
  /* 221. __RSC_select */ NULL,
  /* 222. __RSC_semctl */ NULL,
  /* 223. __RSC_semget */ NULL,
  /* 224. __RSC_semop */ NULL,
  /* 225. __RSC_semtimedop */ NULL,
  /* 226. __RSC_send */ rscs_pre_send_exec,
  /* 227. __RSC_sendfile */ NULL,
  /* 228. __RSC_sendfile64 */ NULL,
  /* 229. __RSC_sendmsg */ NULL,
  /* 230. __RSC_sendto */ rscs_pre_sendto_exec,
  /* 231. __RSC_set_mempolicy */ NULL,
  /* 232. __RSC_set_thread_area */ NULL,
  /* 233. __RSC_set_tid_address */ NULL,
  /* 234. __RSC_setdomainname */ rscs_pre_setdomainname_exec,
  /* 235. __RSC_setfsgid */ NULL,
  /* 236. __RSC_setfsgid32 */ NULL,
  /* 237. __RSC_setfsuid */ NULL,
  /* 238. __RSC_setfsuid32 */ NULL,
  /* 239. __RSC_setgid */ NULL,
  /* 240. __RSC_setgid32 */ NULL,
  /* 241. __RSC_setgroups */ NULL,
  /* 242. __RSC_setgroups32 */ NULL,
  /* 243. __RSC_sethostname */ rscs_pre_sethostname_exec,
  /* 244. __RSC_setitimer */ NULL,
  /* 245. __RSC_setpgid */ NULL,
  /* 246. __RSC_setpriority */ NULL,
  /* 247. __RSC_setregid */ NULL,
  /* 248. __RSC_setregid32 */ NULL,
  /* 249. __RSC_setresgid */ NULL,
  /* 250. __RSC_setresgid32 */ NULL,
  /* 251. __RSC_setresuid */ NULL,
  /* 252. __RSC_setresuid32 */ NULL,
  /* 253. __RSC_setreuid */ NULL,
  /* 254. __RSC_setreuid32 */ NULL,
  /* 255. __RSC_setrlimit */ NULL,
  /* 256. __RSC_setsid */ NULL,
  /* 257. __RSC_setsockopt */ rscs_pre_setsockopt_exec,
  /* 258. __RSC_settimeofday */ rscs_pre_settimeofday_exec,
  /* 259. __RSC_setuid */ NULL,
  /* 260. __RSC_setuid32 */ NULL,
  /* 261. __RSC_setxattr */ NULL,
  /* 262. __RSC_sgetmask */ NULL,
  /* 263. __RSC_shmat */ NULL,
  /* 264. __RSC_shmctl */ NULL,
  /* 265. __RSC_shmdt */ NULL,
  /* 266. __RSC_shmget */ NULL,
  /* 267. __RSC_shutdown */ rscs_pre_shutdown_exec,
  /* 268. __RSC_sigaction */ NULL,
  /* 269. __RSC_sigaltstack */ NULL,
  /* 270. __RSC_signal */ NULL,
  /* 271. __RSC_sigpending */ NULL,
  /* 272. __RSC_sigprocmask */ NULL,
  /* 273. __RSC_sigreturn */ NULL,
  /* 274. __RSC_sigsuspend */ NULL,
  /* 275. __RSC_socket */ rscs_pre_socket_exec,
  /* 276. __RSC_socketcall */ NULL,
  /* 277. __RSC_socketpair */ NULL,
  /* 278. __RSC_ssetmask */ NULL,
  /* 279. __RSC_stat */ NULL,
  /* 280. __RSC_stat64 */ rscs_pre_stat64_exec,
  /* 281. __RSC_statfs */ NULL,
  /* 282. __RSC_statfs64 */ rscs_pre_statfs64_exec,
  /* 283. __RSC_stime */ NULL,
  /* 284. __RSC_stty */ NULL,
  /* 285. __RSC_swapcontext */ NULL,
  /* 286. __RSC_swapoff */ NULL,
  /* 287. __RSC_swapon */ NULL,
  /* 288. __RSC_symlink */ rscs_pre_symlink_exec,
  /* 289. __RSC_sync */ NULL,
  /* 290. __RSC_sys_kexec_load */ NULL,
  /* 291. __RSC_sysfs */ NULL,
  /* 292. __RSC_sysinfo */ NULL,
  /* 293. __RSC_syslog */ NULL,
  /* 294. __RSC_tgkill */ NULL,
  /* 295. __RSC_time */ NULL,
  /* 296. __RSC_timer_create */ NULL,
  /* 297. __RSC_timer_delete */ NULL,
  /* 298. __RSC_timer_getoverrun */ NULL,
  /* 299. __RSC_timer_gettime */ NULL,
  /* 300. __RSC_timer_settime */ NULL,
  /* 301. __RSC_times */ NULL,
  /* 302. __RSC_tkill */ NULL,
  /* 303. __RSC_truncate */ NULL,
  /* 304. __RSC_truncate64 */ rscs_pre_truncate64_exec,
  /* 305. __RSC_tuxcall */ NULL,
  /* 306. __RSC_ugetrlimit */ NULL,
  /* 307. __RSC_ulimit */ NULL,
  /* 308. __RSC_umask */ NULL,
  /* 309. __RSC_umount */ NULL,
  /* 310. __RSC_umount2 */ rscs_pre_umount2_exec,
  /* 311. __RSC_uname */ rscs_pre_uname_exec,
  /* 312. __RSC_unlink */ rscs_pre_unlink_exec,
  /* 313. __RSC_uselib */ NULL,
  /* 314. __RSC_ustat */ NULL,
  /* 315. __RSC_utime */ rscs_pre_utime_exec,
  /* 316. __RSC_utimes */ rscs_pre_utimes_exec,
  /* 317. __RSC_vfork */ NULL,
  /* 318. __RSC_vhangup */ NULL,
  /* 319. __RSC_vm86 */ NULL,
  /* 320. __RSC_vm86old */ NULL,
  /* 321. __RSC_vserver */ NULL,
  /* 322. __RSC_wait4 */ NULL,
  /* 323. __RSC_waitid */ NULL,
  /* 324. __RSC_waitpid */ NULL,
  /* 325. __RSC_write */ rscs_pre_write_exec,
  /* 326. __RSC_writev */ NULL
};

rscs_exec rscs_exec_table[] = {
  /* 0. __RSC__exit */ NULL,
  /* 1. __RSC__llseek */ rscs_exec__llseek,
  /* 2. __RSC__newselect */ NULL,
  /* 3. __RSC__sysctl */ NULL,
  /* 4. __RSC_accept */ rscs_exec_accept,
  /* 5. __RSC_access */ rscs_exec_access,
  /* 6. __RSC_acct */ NULL,
  /* 7. __RSC_add_key */ NULL,
  /* 8. __RSC_adjtimex */ rscs_exec_adjtimex,
  /* 9. __RSC_afs_syscall */ NULL,
  /* 10. __RSC_alarm */ NULL,
  /* 11. __RSC_arch_prctl */ NULL,
  /* 12. __RSC_bdflush */ NULL,
  /* 13. __RSC_bind */ rscs_exec_bind,
  /* 14. __RSC_break */ NULL,
  /* 15. __RSC_brk */ NULL,
  /* 16. __RSC_capget */ NULL,
  /* 17. __RSC_capset */ NULL,
  /* 18. __RSC_chdir */ rscs_exec_chdir,
  /* 19. __RSC_chmod */ rscs_exec_chmod,
  /* 20. __RSC_chown */ rscs_exec_chown,
  /* 21. __RSC_chown32 */ rscs_exec_chown32,
  /* 22. __RSC_chroot */ NULL,
  /* 23. __RSC_clock_getres */ rscs_exec_clock_getres,
  /* 24. __RSC_clock_gettime */ rscs_exec_clock_gettime,
  /* 25. __RSC_clock_nanosleep */ NULL,
  /* 26. __RSC_clock_settime */ rscs_exec_clock_settime,
  /* 27. __RSC_clone */ NULL,
  /* 28. __RSC_close */ rscs_exec_close,
  /* 29. __RSC_connect */ rscs_exec_connect,
  /* 30. __RSC_creat */ NULL,
  /* 31. __RSC_create_module */ NULL,
  /* 32. __RSC_delete_module */ NULL,
  /* 33. __RSC_dup */ rscs_exec_dup,
  /* 34. __RSC_dup2 */ rscs_exec_dup2,
  /* 35. __RSC_epoll_create */ NULL,
  /* 36. __RSC_epoll_ctl */ NULL,
  /* 37. __RSC_epoll_ctl_old */ NULL,
  /* 38. __RSC_epoll_wait */ NULL,
  /* 39. __RSC_epoll_wait_old */ NULL,
  /* 40. __RSC_execve */ NULL,
  /* 41. __RSC_exit */ NULL,
  /* 42. __RSC_exit_group */ NULL,
  /* 43. __RSC_fadvise64 */ NULL,
  /* 44. __RSC_fadvise64_64 */ NULL,
  /* 45. __RSC_fchdir */ rscs_exec_fchdir,
  /* 46. __RSC_fchmod */ rscs_exec_fchmod,
  /* 47. __RSC_fchown */ rscs_exec_fchown,
  /* 48. __RSC_fchown32 */ rscs_exec_fchown32,
  /* 49. __RSC_fcntl */ rscs_exec_fcntl,
  /* 50. __RSC_fcntl64 */ NULL,
  /* 51. __RSC_fdatasync */ rscs_exec_fdatasync,
  /* 52. __RSC_fgetxattr */ rscs_exec_fgetxattr,
  /* 53. __RSC_flistxattr */ NULL,
  /* 54. __RSC_flock */ NULL,
  /* 55. __RSC_fork */ NULL,
  /* 56. __RSC_fremovexattr */ NULL,
  /* 57. __RSC_fsetxattr */ NULL,
  /* 58. __RSC_fstat */ NULL,
  /* 59. __RSC_fstat64 */ rscs_exec_fstat64,
  /* 60. __RSC_fstatfs */ NULL,
  /* 61. __RSC_fstatfs64 */ rscs_exec_fstatfs64,
  /* 62. __RSC_fsync */ rscs_exec_fsync,
  /* 63. __RSC_ftime */ NULL,
  /* 64. __RSC_ftruncate */ NULL,
  /* 65. __RSC_ftruncate64 */ rscs_exec_ftruncate64,
  /* 66. __RSC_futex */ NULL,
  /* 67. __RSC_get_kernel_syms */ NULL,
  /* 68. __RSC_get_mempolicy */ NULL,
  /* 69. __RSC_get_thread_area */ NULL,
  /* 70. __RSC_getcwd */ NULL,
  /* 71. __RSC_getdents */ NULL,
  /* 72. __RSC_getdents64 */ rscs_exec_getdents64,
  /* 73. __RSC_getegid */ NULL,
  /* 74. __RSC_getegid32 */ NULL,
  /* 75. __RSC_geteuid */ NULL,
  /* 76. __RSC_geteuid32 */ NULL,
  /* 77. __RSC_getgid */ NULL,
  /* 78. __RSC_getgid32 */ NULL,
  /* 79. __RSC_getgroups */ NULL,
  /* 80. __RSC_getgroups32 */ NULL,
  /* 81. __RSC_getitimer */ NULL,
  /* 82. __RSC_getpeername */ rscs_exec_getpeername,
  /* 83. __RSC_getpgid */ NULL,
  /* 84. __RSC_getpgrp */ NULL,
  /* 85. __RSC_getpid */ NULL,
  /* 86. __RSC_getpmsg */ NULL,
  /* 87. __RSC_getppid */ NULL,
  /* 88. __RSC_getpriority */ NULL,
  /* 89. __RSC_getresgid */ NULL,
  /* 90. __RSC_getresgid32 */ NULL,
  /* 91. __RSC_getresuid */ NULL,
  /* 92. __RSC_getresuid32 */ NULL,
  /* 93. __RSC_getrlimit */ NULL,
  /* 94. __RSC_getrusage */ NULL,
  /* 95. __RSC_getsid */ NULL,
  /* 96. __RSC_getsockname */ rscs_exec_getsockname,
  /* 97. __RSC_getsockopt */ rscs_exec_getsockopt,
  /* 98. __RSC_gettid */ NULL,
  /* 99. __RSC_gettimeofday */ rscs_exec_gettimeofday,
  /* 100. __RSC_getuid */ NULL,
  /* 101. __RSC_getuid32 */ NULL,
  /* 102. __RSC_getxattr */ rscs_exec_getxattr,
  /* 103. __RSC_gtty */ NULL,
  /* 104. __RSC_idle */ NULL,
  /* 105. __RSC_init_module */ NULL,
  /* 106. __RSC_io_cancel */ NULL,
  /* 107. __RSC_io_destroy */ NULL,
  /* 108. __RSC_io_getevents */ NULL,
  /* 109. __RSC_io_setup */ NULL,
  /* 110. __RSC_io_submit */ NULL,
  /* 111. __RSC_ioctl */ rscs_exec_ioctl,
  /* 112. __RSC_ioperm */ NULL,
  /* 113. __RSC_iopl */ NULL,
  /* 114. __RSC_ipc */ NULL,
  /* 115. __RSC_kexec_load */ NULL,
  /* 116. __RSC_keyctl */ NULL,
  /* 117. __RSC_kill */ NULL,
  /* 118. __RSC_lchown */ rscs_exec_lchown,
  /* 119. __RSC_lchown32 */ rscs_exec_lchown32,
  /* 120. __RSC_lgetxattr */ rscs_exec_lgetxattr,
  /* 121. __RSC_link */ rscs_exec_link,
  /* 122. __RSC_listen */ rscs_exec_listen,
  /* 123. __RSC_listxattr */ NULL,
  /* 124. __RSC_llistxattr */ NULL,
  /* 125. __RSC_lock */ NULL,
  /* 126. __RSC_lookup_dcookie */ NULL,
  /* 127. __RSC_lremovexattr */ NULL,
  /* 128. __RSC_lseek */ rscs_exec_lseek,
  /* 129. __RSC_lsetxattr */ NULL,
  /* 130. __RSC_lstat */ NULL,
  /* 131. __RSC_lstat64 */ rscs_exec_lstat64,
  /* 132. __RSC_madvise */ NULL,
  /* 133. __RSC_madvise1 */ NULL,
  /* 134. __RSC_mbind */ NULL,
  /* 135. __RSC_mincore */ NULL,
  /* 136. __RSC_mkdir */ rscs_exec_mkdir,
  /* 137. __RSC_mknod */ NULL,
  /* 138. __RSC_mlock */ NULL,
  /* 139. __RSC_mlockall */ NULL,
  /* 140. __RSC_mmap */ NULL,
  /* 141. __RSC_mmap2 */ NULL,
  /* 142. __RSC_modify_ldt */ NULL,
  /* 143. __RSC_mount */ rscs_exec_mount,
  /* 144. __RSC_mprotect */ NULL,
  /* 145. __RSC_mpx */ NULL,
  /* 146. __RSC_mq_getsetattr */ NULL,
  /* 147. __RSC_mq_notify */ NULL,
  /* 148. __RSC_mq_open */ NULL,
  /* 149. __RSC_mq_timedreceive */ NULL,
  /* 150. __RSC_mq_timedsend */ NULL,
  /* 151. __RSC_mq_unlink */ NULL,
  /* 152. __RSC_mremap */ NULL,
  /* 153. __RSC_msgctl */ NULL,
  /* 154. __RSC_msgget */ NULL,
  /* 155. __RSC_msgrcv */ NULL,
  /* 156. __RSC_msgsnd */ NULL,
  /* 157. __RSC_msync */ NULL,
  /* 158. __RSC_multiplexer */ NULL,
  /* 159. __RSC_munlock */ NULL,
  /* 160. __RSC_munlockall */ NULL,
  /* 161. __RSC_munmap */ NULL,
  /* 162. __RSC_nanosleep */ NULL,
  /* 163. __RSC_nfsservctl */ NULL,
  /* 164. __RSC_nice */ NULL,
  /* 165. __RSC_oldfstat */ NULL,
  /* 166. __RSC_oldlstat */ NULL,
  /* 167. __RSC_oldolduname */ NULL,
  /* 168. __RSC_oldstat */ NULL,
  /* 169. __RSC_olduname */ NULL,
  /* 170. __RSC_open */ rscs_exec_open,
  /* 171. __RSC_pause */ NULL,
  /* 172. __RSC_pciconfig_iobase */ NULL,
  /* 173. __RSC_pciconfig_read */ NULL,
  /* 174. __RSC_pciconfig_write */ NULL,
  /* 175. __RSC_personality */ NULL,
  /* 176. __RSC_pipe */ NULL,
  /* 177. __RSC_pivot_root */ NULL,
  /* 178. __RSC_poll */ NULL,
  /* 179. __RSC_prctl */ NULL,
  /* 180. __RSC_pread64 */ rscs_exec_pread64,
  /* 181. __RSC_prof */ NULL,
  /* 182. __RSC_profil */ NULL,
  /* 183. __RSC_ptrace */ NULL,
  /* 184. __RSC_putpmsg */ NULL,
  /* 185. __RSC_pwrite64 */ rscs_exec_pwrite64,
  /* 186. __RSC_query_module */ NULL,
  /* 187. __RSC_quotactl */ NULL,
  /* 188. __RSC_read */ rscs_exec_read,
  /* 189. __RSC_readahead */ NULL,
  /* 190. __RSC_readdir */ NULL,
  /* 191. __RSC_readlink */ rscs_exec_readlink,
  /* 192. __RSC_readv */ NULL,
  /* 193. __RSC_reboot */ NULL,
  /* 194. __RSC_recv */ rscs_exec_recv,
  /* 195. __RSC_recvfrom */ rscs_exec_recvfrom,
  /* 196. __RSC_recvmsg */ NULL,
  /* 197. __RSC_remap_file_pages */ NULL,
  /* 198. __RSC_removexattr */ NULL,
  /* 199. __RSC_rename */ rscs_exec_rename,
  /* 200. __RSC_request_key */ NULL,
  /* 201. __RSC_restart_syscall */ NULL,
  /* 202. __RSC_rmdir */ rscs_exec_rmdir,
  /* 203. __RSC_rt_sigaction */ NULL,
  /* 204. __RSC_rt_sigpending */ NULL,
  /* 205. __RSC_rt_sigprocmask */ NULL,
  /* 206. __RSC_rt_sigqueueinfo */ NULL,
  /* 207. __RSC_rt_sigreturn */ NULL,
  /* 208. __RSC_rt_sigsuspend */ NULL,
  /* 209. __RSC_rt_sigtimedwait */ NULL,
  /* 210. __RSC_sched_get_priority_max */ NULL,
  /* 211. __RSC_sched_get_priority_min */ NULL,
  /* 212. __RSC_sched_getaffinity */ NULL,
  /* 213. __RSC_sched_getparam */ NULL,
  /* 214. __RSC_sched_getscheduler */ NULL,
  /* 215. __RSC_sched_rr_get_interval */ NULL,
  /* 216. __RSC_sched_setaffinity */ NULL,
  /* 217. __RSC_sched_setparam */ NULL,
  /* 218. __RSC_sched_setscheduler */ NULL,
  /* 219. __RSC_sched_yield */ NULL,
  /* 220. __RSC_security */ NULL,
  /* 221. __RSC_select */ NULL,
  /* 222. __RSC_semctl */ NULL,
  /* 223. __RSC_semget */ NULL,
  /* 224. __RSC_semop */ NULL,
  /* 225. __RSC_semtimedop */ NULL,
  /* 226. __RSC_send */ rscs_exec_send,
  /* 227. __RSC_sendfile */ NULL,
  /* 228. __RSC_sendfile64 */ NULL,
  /* 229. __RSC_sendmsg */ NULL,
  /* 230. __RSC_sendto */ rscs_exec_sendto,
  /* 231. __RSC_set_mempolicy */ NULL,
  /* 232. __RSC_set_thread_area */ NULL,
  /* 233. __RSC_set_tid_address */ NULL,
  /* 234. __RSC_setdomainname */ rscs_exec_setdomainname,
  /* 235. __RSC_setfsgid */ NULL,
  /* 236. __RSC_setfsgid32 */ NULL,
  /* 237. __RSC_setfsuid */ NULL,
  /* 238. __RSC_setfsuid32 */ NULL,
  /* 239. __RSC_setgid */ NULL,
  /* 240. __RSC_setgid32 */ NULL,
  /* 241. __RSC_setgroups */ NULL,
  /* 242. __RSC_setgroups32 */ NULL,
  /* 243. __RSC_sethostname */ rscs_exec_sethostname,
  /* 244. __RSC_setitimer */ NULL,
  /* 245. __RSC_setpgid */ NULL,
  /* 246. __RSC_setpriority */ NULL,
  /* 247. __RSC_setregid */ NULL,
  /* 248. __RSC_setregid32 */ NULL,
  /* 249. __RSC_setresgid */ NULL,
  /* 250. __RSC_setresgid32 */ NULL,
  /* 251. __RSC_setresuid */ NULL,
  /* 252. __RSC_setresuid32 */ NULL,
  /* 253. __RSC_setreuid */ NULL,
  /* 254. __RSC_setreuid32 */ NULL,
  /* 255. __RSC_setrlimit */ NULL,
  /* 256. __RSC_setsid */ NULL,
  /* 257. __RSC_setsockopt */ rscs_exec_setsockopt,
  /* 258. __RSC_settimeofday */ rscs_exec_settimeofday,
  /* 259. __RSC_setuid */ NULL,
  /* 260. __RSC_setuid32 */ NULL,
  /* 261. __RSC_setxattr */ NULL,
  /* 262. __RSC_sgetmask */ NULL,
  /* 263. __RSC_shmat */ NULL,
  /* 264. __RSC_shmctl */ NULL,
  /* 265. __RSC_shmdt */ NULL,
  /* 266. __RSC_shmget */ NULL,
  /* 267. __RSC_shutdown */ rscs_exec_shutdown,
  /* 268. __RSC_sigaction */ NULL,
  /* 269. __RSC_sigaltstack */ NULL,
  /* 270. __RSC_signal */ NULL,
  /* 271. __RSC_sigpending */ NULL,
  /* 272. __RSC_sigprocmask */ NULL,
  /* 273. __RSC_sigreturn */ NULL,
  /* 274. __RSC_sigsuspend */ NULL,
  /* 275. __RSC_socket */ rscs_exec_socket,
  /* 276. __RSC_socketcall */ NULL,
  /* 277. __RSC_socketpair */ NULL,
  /* 278. __RSC_ssetmask */ NULL,
  /* 279. __RSC_stat */ NULL,
  /* 280. __RSC_stat64 */ rscs_exec_stat64,
  /* 281. __RSC_statfs */ NULL,
  /* 282. __RSC_statfs64 */ rscs_exec_statfs64,
  /* 283. __RSC_stime */ NULL,
  /* 284. __RSC_stty */ NULL,
  /* 285. __RSC_swapcontext */ NULL,
  /* 286. __RSC_swapoff */ NULL,
  /* 287. __RSC_swapon */ NULL,
  /* 288. __RSC_symlink */ rscs_exec_symlink,
  /* 289. __RSC_sync */ NULL,
  /* 290. __RSC_sys_kexec_load */ NULL,
  /* 291. __RSC_sysfs */ NULL,
  /* 292. __RSC_sysinfo */ NULL,
  /* 293. __RSC_syslog */ NULL,
  /* 294. __RSC_tgkill */ NULL,
  /* 295. __RSC_time */ NULL,
  /* 296. __RSC_timer_create */ NULL,
  /* 297. __RSC_timer_delete */ NULL,
  /* 298. __RSC_timer_getoverrun */ NULL,
  /* 299. __RSC_timer_gettime */ NULL,
  /* 300. __RSC_timer_settime */ NULL,
  /* 301. __RSC_times */ NULL,
  /* 302. __RSC_tkill */ NULL,
  /* 303. __RSC_truncate */ NULL,
  /* 304. __RSC_truncate64 */ rscs_exec_truncate64,
  /* 305. __RSC_tuxcall */ NULL,
  /* 306. __RSC_ugetrlimit */ NULL,
  /* 307. __RSC_ulimit */ NULL,
  /* 308. __RSC_umask */ NULL,
  /* 309. __RSC_umount */ NULL,
  /* 310. __RSC_umount2 */ rscs_exec_umount2,
  /* 311. __RSC_uname */ rscs_exec_uname,
  /* 312. __RSC_unlink */ rscs_exec_unlink,
  /* 313. __RSC_uselib */ NULL,
  /* 314. __RSC_ustat */ NULL,
  /* 315. __RSC_utime */ rscs_exec_utime,
  /* 316. __RSC_utimes */ rscs_exec_utimes,
  /* 317. __RSC_vfork */ NULL,
  /* 318. __RSC_vhangup */ NULL,
  /* 319. __RSC_vm86 */ NULL,
  /* 320. __RSC_vm86old */ NULL,
  /* 321. __RSC_vserver */ NULL,
  /* 322. __RSC_wait4 */ NULL,
  /* 323. __RSC_waitid */ NULL,
  /* 324. __RSC_waitpid */ NULL,
  /* 325. __RSC_write */ rscs_exec_write,
  /* 326. __RSC_writev */ NULL
};

rscs_post_exec rscs_post_exec_table[] = {
  /* 0. __RSC__exit */ NULL,
  /* 1. __RSC__llseek */ rscs_post__llseek_exec,
  /* 2. __RSC__newselect */ NULL,
  /* 3. __RSC__sysctl */ NULL,
  /* 4. __RSC_accept */ rscs_post_accept_exec,
  /* 5. __RSC_access */ rscs_post_access_exec,
  /* 6. __RSC_acct */ NULL,
  /* 7. __RSC_add_key */ NULL,
  /* 8. __RSC_adjtimex */ rscs_post_adjtimex_exec,
  /* 9. __RSC_afs_syscall */ NULL,
  /* 10. __RSC_alarm */ NULL,
  /* 11. __RSC_arch_prctl */ NULL,
  /* 12. __RSC_bdflush */ NULL,
  /* 13. __RSC_bind */ rscs_post_bind_exec,
  /* 14. __RSC_break */ NULL,
  /* 15. __RSC_brk */ NULL,
  /* 16. __RSC_capget */ NULL,
  /* 17. __RSC_capset */ NULL,
  /* 18. __RSC_chdir */ rscs_post_chdir_exec,
  /* 19. __RSC_chmod */ rscs_post_chmod_exec,
  /* 20. __RSC_chown */ rscs_post_chown_exec,
  /* 21. __RSC_chown32 */ rscs_post_chown32_exec,
  /* 22. __RSC_chroot */ NULL,
  /* 23. __RSC_clock_getres */ rscs_post_clock_getres_exec,
  /* 24. __RSC_clock_gettime */ rscs_post_clock_gettime_exec,
  /* 25. __RSC_clock_nanosleep */ NULL,
  /* 26. __RSC_clock_settime */ rscs_post_clock_settime_exec,
  /* 27. __RSC_clone */ NULL,
  /* 28. __RSC_close */ rscs_post_close_exec,
  /* 29. __RSC_connect */ rscs_post_connect_exec,
  /* 30. __RSC_creat */ NULL,
  /* 31. __RSC_create_module */ NULL,
  /* 32. __RSC_delete_module */ NULL,
  /* 33. __RSC_dup */ rscs_post_dup_exec,
  /* 34. __RSC_dup2 */ rscs_post_dup2_exec,
  /* 35. __RSC_epoll_create */ NULL,
  /* 36. __RSC_epoll_ctl */ NULL,
  /* 37. __RSC_epoll_ctl_old */ NULL,
  /* 38. __RSC_epoll_wait */ NULL,
  /* 39. __RSC_epoll_wait_old */ NULL,
  /* 40. __RSC_execve */ NULL,
  /* 41. __RSC_exit */ NULL,
  /* 42. __RSC_exit_group */ NULL,
  /* 43. __RSC_fadvise64 */ NULL,
  /* 44. __RSC_fadvise64_64 */ NULL,
  /* 45. __RSC_fchdir */ rscs_post_fchdir_exec,
  /* 46. __RSC_fchmod */ rscs_post_fchmod_exec,
  /* 47. __RSC_fchown */ rscs_post_fchown_exec,
  /* 48. __RSC_fchown32 */ rscs_post_fchown32_exec,
  /* 49. __RSC_fcntl */ rscs_post_fcntl_exec,
  /* 50. __RSC_fcntl64 */ NULL,
  /* 51. __RSC_fdatasync */ rscs_post_fdatasync_exec,
  /* 52. __RSC_fgetxattr */ rscs_post_fgetxattr_exec,
  /* 53. __RSC_flistxattr */ NULL,
  /* 54. __RSC_flock */ NULL,
  /* 55. __RSC_fork */ NULL,
  /* 56. __RSC_fremovexattr */ NULL,
  /* 57. __RSC_fsetxattr */ NULL,
  /* 58. __RSC_fstat */ NULL,
  /* 59. __RSC_fstat64 */ rscs_post_fstat64_exec,
  /* 60. __RSC_fstatfs */ NULL,
  /* 61. __RSC_fstatfs64 */ rscs_post_fstatfs64_exec,
  /* 62. __RSC_fsync */ rscs_post_fsync_exec,
  /* 63. __RSC_ftime */ NULL,
  /* 64. __RSC_ftruncate */ NULL,
  /* 65. __RSC_ftruncate64 */ rscs_post_ftruncate64_exec,
  /* 66. __RSC_futex */ NULL,
  /* 67. __RSC_get_kernel_syms */ NULL,
  /* 68. __RSC_get_mempolicy */ NULL,
  /* 69. __RSC_get_thread_area */ NULL,
  /* 70. __RSC_getcwd */ NULL,
  /* 71. __RSC_getdents */ NULL,
  /* 72. __RSC_getdents64 */ rscs_post_getdents64_exec,
  /* 73. __RSC_getegid */ NULL,
  /* 74. __RSC_getegid32 */ NULL,
  /* 75. __RSC_geteuid */ NULL,
  /* 76. __RSC_geteuid32 */ NULL,
  /* 77. __RSC_getgid */ NULL,
  /* 78. __RSC_getgid32 */ NULL,
  /* 79. __RSC_getgroups */ NULL,
  /* 80. __RSC_getgroups32 */ NULL,
  /* 81. __RSC_getitimer */ NULL,
  /* 82. __RSC_getpeername */ rscs_post_getpeername_exec,
  /* 83. __RSC_getpgid */ NULL,
  /* 84. __RSC_getpgrp */ NULL,
  /* 85. __RSC_getpid */ NULL,
  /* 86. __RSC_getpmsg */ NULL,
  /* 87. __RSC_getppid */ NULL,
  /* 88. __RSC_getpriority */ NULL,
  /* 89. __RSC_getresgid */ NULL,
  /* 90. __RSC_getresgid32 */ NULL,
  /* 91. __RSC_getresuid */ NULL,
  /* 92. __RSC_getresuid32 */ NULL,
  /* 93. __RSC_getrlimit */ NULL,
  /* 94. __RSC_getrusage */ NULL,
  /* 95. __RSC_getsid */ NULL,
  /* 96. __RSC_getsockname */ rscs_post_getsockname_exec,
  /* 97. __RSC_getsockopt */ rscs_post_getsockopt_exec,
  /* 98. __RSC_gettid */ NULL,
  /* 99. __RSC_gettimeofday */ rscs_post_gettimeofday_exec,
  /* 100. __RSC_getuid */ NULL,
  /* 101. __RSC_getuid32 */ NULL,
  /* 102. __RSC_getxattr */ rscs_post_getxattr_exec,
  /* 103. __RSC_gtty */ NULL,
  /* 104. __RSC_idle */ NULL,
  /* 105. __RSC_init_module */ NULL,
  /* 106. __RSC_io_cancel */ NULL,
  /* 107. __RSC_io_destroy */ NULL,
  /* 108. __RSC_io_getevents */ NULL,
  /* 109. __RSC_io_setup */ NULL,
  /* 110. __RSC_io_submit */ NULL,
  /* 111. __RSC_ioctl */ rscs_post_ioctl_exec,
  /* 112. __RSC_ioperm */ NULL,
  /* 113. __RSC_iopl */ NULL,
  /* 114. __RSC_ipc */ NULL,
  /* 115. __RSC_kexec_load */ NULL,
  /* 116. __RSC_keyctl */ NULL,
  /* 117. __RSC_kill */ NULL,
  /* 118. __RSC_lchown */ rscs_post_lchown_exec,
  /* 119. __RSC_lchown32 */ rscs_post_lchown32_exec,
  /* 120. __RSC_lgetxattr */ rscs_post_lgetxattr_exec,
  /* 121. __RSC_link */ rscs_post_link_exec,
  /* 122. __RSC_listen */ rscs_post_listen_exec,
  /* 123. __RSC_listxattr */ NULL,
  /* 124. __RSC_llistxattr */ NULL,
  /* 125. __RSC_lock */ NULL,
  /* 126. __RSC_lookup_dcookie */ NULL,
  /* 127. __RSC_lremovexattr */ NULL,
  /* 128. __RSC_lseek */ rscs_post_lseek_exec,
  /* 129. __RSC_lsetxattr */ NULL,
  /* 130. __RSC_lstat */ NULL,
  /* 131. __RSC_lstat64 */ rscs_post_lstat64_exec,
  /* 132. __RSC_madvise */ NULL,
  /* 133. __RSC_madvise1 */ NULL,
  /* 134. __RSC_mbind */ NULL,
  /* 135. __RSC_mincore */ NULL,
  /* 136. __RSC_mkdir */ rscs_post_mkdir_exec,
  /* 137. __RSC_mknod */ NULL,
  /* 138. __RSC_mlock */ NULL,
  /* 139. __RSC_mlockall */ NULL,
  /* 140. __RSC_mmap */ NULL,
  /* 141. __RSC_mmap2 */ NULL,
  /* 142. __RSC_modify_ldt */ NULL,
  /* 143. __RSC_mount */ rscs_post_mount_exec,
  /* 144. __RSC_mprotect */ NULL,
  /* 145. __RSC_mpx */ NULL,
  /* 146. __RSC_mq_getsetattr */ NULL,
  /* 147. __RSC_mq_notify */ NULL,
  /* 148. __RSC_mq_open */ NULL,
  /* 149. __RSC_mq_timedreceive */ NULL,
  /* 150. __RSC_mq_timedsend */ NULL,
  /* 151. __RSC_mq_unlink */ NULL,
  /* 152. __RSC_mremap */ NULL,
  /* 153. __RSC_msgctl */ NULL,
  /* 154. __RSC_msgget */ NULL,
  /* 155. __RSC_msgrcv */ NULL,
  /* 156. __RSC_msgsnd */ NULL,
  /* 157. __RSC_msync */ NULL,
  /* 158. __RSC_multiplexer */ NULL,
  /* 159. __RSC_munlock */ NULL,
  /* 160. __RSC_munlockall */ NULL,
  /* 161. __RSC_munmap */ NULL,
  /* 162. __RSC_nanosleep */ NULL,
  /* 163. __RSC_nfsservctl */ NULL,
  /* 164. __RSC_nice */ NULL,
  /* 165. __RSC_oldfstat */ NULL,
  /* 166. __RSC_oldlstat */ NULL,
  /* 167. __RSC_oldolduname */ NULL,
  /* 168. __RSC_oldstat */ NULL,
  /* 169. __RSC_olduname */ NULL,
  /* 170. __RSC_open */ rscs_post_open_exec,
  /* 171. __RSC_pause */ NULL,
  /* 172. __RSC_pciconfig_iobase */ NULL,
  /* 173. __RSC_pciconfig_read */ NULL,
  /* 174. __RSC_pciconfig_write */ NULL,
  /* 175. __RSC_personality */ NULL,
  /* 176. __RSC_pipe */ NULL,
  /* 177. __RSC_pivot_root */ NULL,
  /* 178. __RSC_poll */ NULL,
  /* 179. __RSC_prctl */ NULL,
  /* 180. __RSC_pread64 */ rscs_post_pread64_exec,
  /* 181. __RSC_prof */ NULL,
  /* 182. __RSC_profil */ NULL,
  /* 183. __RSC_ptrace */ NULL,
  /* 184. __RSC_putpmsg */ NULL,
  /* 185. __RSC_pwrite64 */ rscs_post_pwrite64_exec,
  /* 186. __RSC_query_module */ NULL,
  /* 187. __RSC_quotactl */ NULL,
  /* 188. __RSC_read */ rscs_post_read_exec,
  /* 189. __RSC_readahead */ NULL,
  /* 190. __RSC_readdir */ NULL,
  /* 191. __RSC_readlink */ rscs_post_readlink_exec,
  /* 192. __RSC_readv */ NULL,
  /* 193. __RSC_reboot */ NULL,
  /* 194. __RSC_recv */ rscs_post_recv_exec,
  /* 195. __RSC_recvfrom */ rscs_post_recvfrom_exec,
  /* 196. __RSC_recvmsg */ NULL,
  /* 197. __RSC_remap_file_pages */ NULL,
  /* 198. __RSC_removexattr */ NULL,
  /* 199. __RSC_rename */ rscs_post_rename_exec,
  /* 200. __RSC_request_key */ NULL,
  /* 201. __RSC_restart_syscall */ NULL,
  /* 202. __RSC_rmdir */ rscs_post_rmdir_exec,
  /* 203. __RSC_rt_sigaction */ NULL,
  /* 204. __RSC_rt_sigpending */ NULL,
  /* 205. __RSC_rt_sigprocmask */ NULL,
  /* 206. __RSC_rt_sigqueueinfo */ NULL,
  /* 207. __RSC_rt_sigreturn */ NULL,
  /* 208. __RSC_rt_sigsuspend */ NULL,
  /* 209. __RSC_rt_sigtimedwait */ NULL,
  /* 210. __RSC_sched_get_priority_max */ NULL,
  /* 211. __RSC_sched_get_priority_min */ NULL,
  /* 212. __RSC_sched_getaffinity */ NULL,
  /* 213. __RSC_sched_getparam */ NULL,
  /* 214. __RSC_sched_getscheduler */ NULL,
  /* 215. __RSC_sched_rr_get_interval */ NULL,
  /* 216. __RSC_sched_setaffinity */ NULL,
  /* 217. __RSC_sched_setparam */ NULL,
  /* 218. __RSC_sched_setscheduler */ NULL,
  /* 219. __RSC_sched_yield */ NULL,
  /* 220. __RSC_security */ NULL,
  /* 221. __RSC_select */ NULL,
  /* 222. __RSC_semctl */ NULL,
  /* 223. __RSC_semget */ NULL,
  /* 224. __RSC_semop */ NULL,
  /* 225. __RSC_semtimedop */ NULL,
  /* 226. __RSC_send */ rscs_post_send_exec,
  /* 227. __RSC_sendfile */ NULL,
  /* 228. __RSC_sendfile64 */ NULL,
  /* 229. __RSC_sendmsg */ NULL,
  /* 230. __RSC_sendto */ rscs_post_sendto_exec,
  /* 231. __RSC_set_mempolicy */ NULL,
  /* 232. __RSC_set_thread_area */ NULL,
  /* 233. __RSC_set_tid_address */ NULL,
  /* 234. __RSC_setdomainname */ rscs_post_setdomainname_exec,
  /* 235. __RSC_setfsgid */ NULL,
  /* 236. __RSC_setfsgid32 */ NULL,
  /* 237. __RSC_setfsuid */ NULL,
  /* 238. __RSC_setfsuid32 */ NULL,
  /* 239. __RSC_setgid */ NULL,
  /* 240. __RSC_setgid32 */ NULL,
  /* 241. __RSC_setgroups */ NULL,
  /* 242. __RSC_setgroups32 */ NULL,
  /* 243. __RSC_sethostname */ rscs_post_sethostname_exec,
  /* 244. __RSC_setitimer */ NULL,
  /* 245. __RSC_setpgid */ NULL,
  /* 246. __RSC_setpriority */ NULL,
  /* 247. __RSC_setregid */ NULL,
  /* 248. __RSC_setregid32 */ NULL,
  /* 249. __RSC_setresgid */ NULL,
  /* 250. __RSC_setresgid32 */ NULL,
  /* 251. __RSC_setresuid */ NULL,
  /* 252. __RSC_setresuid32 */ NULL,
  /* 253. __RSC_setreuid */ NULL,
  /* 254. __RSC_setreuid32 */ NULL,
  /* 255. __RSC_setrlimit */ NULL,
  /* 256. __RSC_setsid */ NULL,
  /* 257. __RSC_setsockopt */ rscs_post_setsockopt_exec,
  /* 258. __RSC_settimeofday */ rscs_post_settimeofday_exec,
  /* 259. __RSC_setuid */ NULL,
  /* 260. __RSC_setuid32 */ NULL,
  /* 261. __RSC_setxattr */ NULL,
  /* 262. __RSC_sgetmask */ NULL,
  /* 263. __RSC_shmat */ NULL,
  /* 264. __RSC_shmctl */ NULL,
  /* 265. __RSC_shmdt */ NULL,
  /* 266. __RSC_shmget */ NULL,
  /* 267. __RSC_shutdown */ rscs_post_shutdown_exec,
  /* 268. __RSC_sigaction */ NULL,
  /* 269. __RSC_sigaltstack */ NULL,
  /* 270. __RSC_signal */ NULL,
  /* 271. __RSC_sigpending */ NULL,
  /* 272. __RSC_sigprocmask */ NULL,
  /* 273. __RSC_sigreturn */ NULL,
  /* 274. __RSC_sigsuspend */ NULL,
  /* 275. __RSC_socket */ rscs_post_socket_exec,
  /* 276. __RSC_socketcall */ NULL,
  /* 277. __RSC_socketpair */ NULL,
  /* 278. __RSC_ssetmask */ NULL,
  /* 279. __RSC_stat */ NULL,
  /* 280. __RSC_stat64 */ rscs_post_stat64_exec,
  /* 281. __RSC_statfs */ NULL,
  /* 282. __RSC_statfs64 */ rscs_post_statfs64_exec,
  /* 283. __RSC_stime */ NULL,
  /* 284. __RSC_stty */ NULL,
  /* 285. __RSC_swapcontext */ NULL,
  /* 286. __RSC_swapoff */ NULL,
  /* 287. __RSC_swapon */ NULL,
  /* 288. __RSC_symlink */ rscs_post_symlink_exec,
  /* 289. __RSC_sync */ NULL,
  /* 290. __RSC_sys_kexec_load */ NULL,
  /* 291. __RSC_sysfs */ NULL,
  /* 292. __RSC_sysinfo */ NULL,
  /* 293. __RSC_syslog */ NULL,
  /* 294. __RSC_tgkill */ NULL,
  /* 295. __RSC_time */ NULL,
  /* 296. __RSC_timer_create */ NULL,
  /* 297. __RSC_timer_delete */ NULL,
  /* 298. __RSC_timer_getoverrun */ NULL,
  /* 299. __RSC_timer_gettime */ NULL,
  /* 300. __RSC_timer_settime */ NULL,
  /* 301. __RSC_times */ NULL,
  /* 302. __RSC_tkill */ NULL,
  /* 303. __RSC_truncate */ NULL,
  /* 304. __RSC_truncate64 */ rscs_post_truncate64_exec,
  /* 305. __RSC_tuxcall */ NULL,
  /* 306. __RSC_ugetrlimit */ NULL,
  /* 307. __RSC_ulimit */ NULL,
  /* 308. __RSC_umask */ NULL,
  /* 309. __RSC_umount */ NULL,
  /* 310. __RSC_umount2 */ rscs_post_umount2_exec,
  /* 311. __RSC_uname */ rscs_post_uname_exec,
  /* 312. __RSC_unlink */ rscs_post_unlink_exec,
  /* 313. __RSC_uselib */ NULL,
  /* 314. __RSC_ustat */ NULL,
  /* 315. __RSC_utime */ rscs_post_utime_exec,
  /* 316. __RSC_utimes */ rscs_post_utimes_exec,
  /* 317. __RSC_vfork */ NULL,
  /* 318. __RSC_vhangup */ NULL,
  /* 319. __RSC_vm86 */ NULL,
  /* 320. __RSC_vm86old */ NULL,
  /* 321. __RSC_vserver */ NULL,
  /* 322. __RSC_wait4 */ NULL,
  /* 323. __RSC_waitid */ NULL,
  /* 324. __RSC_waitpid */ NULL,
  /* 325. __RSC_write */ rscs_post_write_exec,
  /* 326. __RSC_writev */ NULL
};

/*########################################################################*/
/*##                                                                    ##*/
/*##  IOCTL MANAGEMENT                                                  ##*/
/*##                                                                    ##*/
/*########################################################################*/
struct ioctl_entry {
  int request; 
  u_int32_t size_type;
};

static int ioctl_entry_compare(void *e, void *request) {
  return ( ((struct ioctl_entry *)e)->request == *((int *)request));
}

#define ioctl_search(request) (list_search(ioctl_list, ioctl_entry_compare, &(request)))
#define ioctl_getel(index) ((struct ioctl_entry *)list_getel(ioctl_list, (index)))
#define free_ioctl_req(ioctl_req)   free(ioctl_req)

void rscs_ioctl_register_request(int request, u_int32_t rw, u_int32_t size) {
  struct ioctl_entry *req;
  req = calloc(1, sizeof(struct ioctl_entry));
  assert(req != NULL);
  req->request = request;
  req->size_type = rw | size;
  list_add(ioctl_list, req);
}


#ifndef RSCDEBUG
static
#endif
struct ioctl_resp_header *rscs_manage_ioctl_request(struct ioctl_req_header *ioctl_req) {
  struct ioctl_entry *res;
  struct ioctl_resp_header *resp;
  int index;
  resp = calloc(1, sizeof(struct ioctl_resp_header));
  assert(resp != NULL);
  
  ioctl_req->req_ioctl_request = ntohl(ioctl_req->req_ioctl_request);
  index = ioctl_search(ioctl_req->req_ioctl_request);
  res = ioctl_getel(index);

  /* I create the answer */
  resp->resp_type = RSC_IOCTL_RESP;
  resp->resp_size = htonl(sizeof(struct ioctl_resp_header));
  if(res == NULL) {
    /* Negative answer */
    resp->resp_size_type = htonl(IOCTL_UNMANAGED);
  } else {
    /* Positive one */
    resp->resp_size_type = htonl(res->size_type);
  }
  return resp;
}

/**************************************************************************/
/***  ADJUST READ POINTERS                                              ***/
/**************************************************************************/
   
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void accept_adjust_read_pointers(struct accept_req *accept_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) accept_req) + sizeof(struct accept_req);
   
  if(accept_req->addrlen != NULL) {
    accept_req->addrlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void access_adjust_read_pointers(struct access_req *access_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) access_req) + sizeof(struct access_req);
   
  if(access_req->pathname != NULL) {
    access_req->pathname = var_data;
    var_data += (strlen(access_req->pathname) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void adjtimex_adjust_read_pointers(struct adjtimex_req *adjtimex_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) adjtimex_req) + sizeof(struct adjtimex_req);
   
  if(adjtimex_req->buf != NULL) {
    adjtimex_req->buf = var_data;
    var_data += sizeof(struct timex); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void bind_adjust_read_pointers(struct bind_req *bind_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) bind_req) + sizeof(struct bind_req);
   
  if(bind_req->my_addr != NULL) {
    bind_req->my_addr = var_data;
    var_data += bind_req->addrlen; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void chdir_adjust_read_pointers(struct chdir_req *chdir_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) chdir_req) + sizeof(struct chdir_req);
   
  if(chdir_req->path != NULL) {
    chdir_req->path = var_data;
    var_data += (strlen(chdir_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void chmod_adjust_read_pointers(struct chmod_req *chmod_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) chmod_req) + sizeof(struct chmod_req);
   
  if(chmod_req->path != NULL) {
    chmod_req->path = var_data;
    var_data += (strlen(chmod_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void chown_adjust_read_pointers(struct chown_req *chown_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) chown_req) + sizeof(struct chown_req);
   
  if(chown_req->path != NULL) {
    chown_req->path = var_data;
    var_data += (strlen(chown_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void chown32_adjust_read_pointers(struct chown32_req *chown32_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) chown32_req) + sizeof(struct chown32_req);
   
  if(chown32_req->path != NULL) {
    chown32_req->path = var_data;
    var_data += (strlen(chown32_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void clock_settime_adjust_read_pointers(struct clock_settime_req *clock_settime_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) clock_settime_req) + sizeof(struct clock_settime_req);
   
  if(clock_settime_req->tp != NULL) {
    clock_settime_req->tp = var_data;
    var_data += sizeof(struct timespec); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void connect_adjust_read_pointers(struct connect_req *connect_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) connect_req) + sizeof(struct connect_req);
   
  if(connect_req->serv_addr != NULL) {
    connect_req->serv_addr = var_data;
    var_data += connect_req->addrlen; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void fgetxattr_adjust_read_pointers(struct fgetxattr_req *fgetxattr_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) fgetxattr_req) + sizeof(struct fgetxattr_req);
   
  if(fgetxattr_req->name != NULL) {
    fgetxattr_req->name = var_data;
    var_data += (strlen(fgetxattr_req->name) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void getpeername_adjust_read_pointers(struct getpeername_req *getpeername_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) getpeername_req) + sizeof(struct getpeername_req);
   
  if(getpeername_req->namelen != NULL) {
    getpeername_req->namelen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void getsockname_adjust_read_pointers(struct getsockname_req *getsockname_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) getsockname_req) + sizeof(struct getsockname_req);
   
  if(getsockname_req->namelen != NULL) {
    getsockname_req->namelen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void getsockopt_adjust_read_pointers(struct getsockopt_req *getsockopt_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) getsockopt_req) + sizeof(struct getsockopt_req);
   
  if(getsockopt_req->optlen != NULL) {
    getsockopt_req->optlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void getxattr_adjust_read_pointers(struct getxattr_req *getxattr_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) getxattr_req) + sizeof(struct getxattr_req);
   
  if(getxattr_req->path != NULL) {
    getxattr_req->path = var_data;
    var_data += (strlen(getxattr_req->path) + 1); 
  }
   
  if(getxattr_req->name != NULL) {
    getxattr_req->name = var_data;
    var_data += (strlen(getxattr_req->name) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void lchown_adjust_read_pointers(struct lchown_req *lchown_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) lchown_req) + sizeof(struct lchown_req);
   
  if(lchown_req->path != NULL) {
    lchown_req->path = var_data;
    var_data += (strlen(lchown_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void lchown32_adjust_read_pointers(struct lchown32_req *lchown32_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) lchown32_req) + sizeof(struct lchown32_req);
   
  if(lchown32_req->path != NULL) {
    lchown32_req->path = var_data;
    var_data += (strlen(lchown32_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void lgetxattr_adjust_read_pointers(struct lgetxattr_req *lgetxattr_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) lgetxattr_req) + sizeof(struct lgetxattr_req);
   
  if(lgetxattr_req->path != NULL) {
    lgetxattr_req->path = var_data;
    var_data += (strlen(lgetxattr_req->path) + 1); 
  }
   
  if(lgetxattr_req->name != NULL) {
    lgetxattr_req->name = var_data;
    var_data += (strlen(lgetxattr_req->name) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void link_adjust_read_pointers(struct link_req *link_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) link_req) + sizeof(struct link_req);
   
  if(link_req->oldpath != NULL) {
    link_req->oldpath = var_data;
    var_data += (strlen(link_req->oldpath) + 1); 
  }
   
  if(link_req->newpath != NULL) {
    link_req->newpath = var_data;
    var_data += (strlen(link_req->newpath) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void lstat64_adjust_read_pointers(struct lstat64_req *lstat64_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) lstat64_req) + sizeof(struct lstat64_req);
   
  if(lstat64_req->path != NULL) {
    lstat64_req->path = var_data;
    var_data += (strlen(lstat64_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void mkdir_adjust_read_pointers(struct mkdir_req *mkdir_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) mkdir_req) + sizeof(struct mkdir_req);
   
  if(mkdir_req->pathname != NULL) {
    mkdir_req->pathname = var_data;
    var_data += (strlen(mkdir_req->pathname) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void mount_adjust_read_pointers(struct mount_req *mount_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) mount_req) + sizeof(struct mount_req);
   
  if(mount_req->source != NULL) {
    mount_req->source = var_data;
    var_data += (strlen(mount_req->source) + 1); 
  }
   
  if(mount_req->target != NULL) {
    mount_req->target = var_data;
    var_data += (strlen(mount_req->target) + 1); 
  }
   
  if(mount_req->filesystemtype != NULL) {
    mount_req->filesystemtype = var_data;
    var_data += (strlen(mount_req->filesystemtype) + 1); 
  }
   
  if(mount_req->data != NULL) {
    mount_req->data = var_data;
    var_data += (strlen(mount_req->data) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void open_adjust_read_pointers(struct open_req *open_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) open_req) + sizeof(struct open_req);
   
  if(open_req->pathname != NULL) {
    open_req->pathname = var_data;
    var_data += (strlen(open_req->pathname) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void pwrite64_adjust_read_pointers(struct pwrite64_req *pwrite64_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) pwrite64_req) + sizeof(struct pwrite64_req);
   
  if(pwrite64_req->buf != NULL) {
    pwrite64_req->buf = var_data;
    var_data += pwrite64_req->count; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void readlink_adjust_read_pointers(struct readlink_req *readlink_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) readlink_req) + sizeof(struct readlink_req);
   
  if(readlink_req->path != NULL) {
    readlink_req->path = var_data;
    var_data += (strlen(readlink_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void recvfrom_adjust_read_pointers(struct recvfrom_req *recvfrom_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) recvfrom_req) + sizeof(struct recvfrom_req);
   
  if(recvfrom_req->fromlen != NULL) {
    recvfrom_req->fromlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
  if(recvfrom_req->from != NULL) {
    recvfrom_req->from = var_data;
    var_data += *(recvfrom_req->fromlen); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void rename_adjust_read_pointers(struct rename_req *rename_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) rename_req) + sizeof(struct rename_req);
   
  if(rename_req->oldpath != NULL) {
    rename_req->oldpath = var_data;
    var_data += (strlen(rename_req->oldpath) + 1); 
  }
   
  if(rename_req->newpath != NULL) {
    rename_req->newpath = var_data;
    var_data += (strlen(rename_req->newpath) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void rmdir_adjust_read_pointers(struct rmdir_req *rmdir_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) rmdir_req) + sizeof(struct rmdir_req);
   
  if(rmdir_req->pathname != NULL) {
    rmdir_req->pathname = var_data;
    var_data += (strlen(rmdir_req->pathname) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void send_adjust_read_pointers(struct send_req *send_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) send_req) + sizeof(struct send_req);
   
  if(send_req->buf != NULL) {
    send_req->buf = var_data;
    var_data += send_req->len; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void sendto_adjust_read_pointers(struct sendto_req *sendto_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) sendto_req) + sizeof(struct sendto_req);
   
  if(sendto_req->buf != NULL) {
    sendto_req->buf = var_data;
    var_data += sendto_req->len; 
  }
   
  if(sendto_req->to != NULL) {
    sendto_req->to = var_data;
    var_data += sendto_req->tolen; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void setdomainname_adjust_read_pointers(struct setdomainname_req *setdomainname_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) setdomainname_req) + sizeof(struct setdomainname_req);
   
  if(setdomainname_req->name != NULL) {
    setdomainname_req->name = var_data;
    var_data += setdomainname_req->len; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void sethostname_adjust_read_pointers(struct sethostname_req *sethostname_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) sethostname_req) + sizeof(struct sethostname_req);
   
  if(sethostname_req->name != NULL) {
    sethostname_req->name = var_data;
    var_data += sethostname_req->len; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void setsockopt_adjust_read_pointers(struct setsockopt_req *setsockopt_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) setsockopt_req) + sizeof(struct setsockopt_req);
   
  if(setsockopt_req->optval != NULL) {
    setsockopt_req->optval = var_data;
    var_data += setsockopt_req->optlen; 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void settimeofday_adjust_read_pointers(struct settimeofday_req *settimeofday_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) settimeofday_req) + sizeof(struct settimeofday_req);
   
  if(settimeofday_req->tv != NULL) {
    settimeofday_req->tv = var_data;
    var_data += sizeof(struct timeval); 
  }
   
  if(settimeofday_req->tz != NULL) {
    settimeofday_req->tz = var_data;
    var_data += sizeof(struct timezone); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void stat64_adjust_read_pointers(struct stat64_req *stat64_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) stat64_req) + sizeof(struct stat64_req);
   
  if(stat64_req->path != NULL) {
    stat64_req->path = var_data;
    var_data += (strlen(stat64_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void statfs64_adjust_read_pointers(struct statfs64_req *statfs64_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) statfs64_req) + sizeof(struct statfs64_req);
   
  if(statfs64_req->path != NULL) {
    statfs64_req->path = var_data;
    var_data += (strlen(statfs64_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void symlink_adjust_read_pointers(struct symlink_req *symlink_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) symlink_req) + sizeof(struct symlink_req);
   
  if(symlink_req->oldpath != NULL) {
    symlink_req->oldpath = var_data;
    var_data += (strlen(symlink_req->oldpath) + 1); 
  }
   
  if(symlink_req->newpath != NULL) {
    symlink_req->newpath = var_data;
    var_data += (strlen(symlink_req->newpath) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void truncate64_adjust_read_pointers(struct truncate64_req *truncate64_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) truncate64_req) + sizeof(struct truncate64_req);
   
  if(truncate64_req->path != NULL) {
    truncate64_req->path = var_data;
    var_data += (strlen(truncate64_req->path) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void umount2_adjust_read_pointers(struct umount2_req *umount2_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) umount2_req) + sizeof(struct umount2_req);
   
  if(umount2_req->target != NULL) {
    umount2_req->target = var_data;
    var_data += (strlen(umount2_req->target) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void unlink_adjust_read_pointers(struct unlink_req *unlink_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) unlink_req) + sizeof(struct unlink_req);
   
  if(unlink_req->pathname != NULL) {
    unlink_req->pathname = var_data;
    var_data += (strlen(unlink_req->pathname) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void utime_adjust_read_pointers(struct utime_req *utime_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) utime_req) + sizeof(struct utime_req);
   
  if(utime_req->filename != NULL) {
    utime_req->filename = var_data;
    var_data += (strlen(utime_req->filename) + 1); 
  }
   
  if(utime_req->buf != NULL) {
    utime_req->buf = var_data;
    var_data += sizeof(struct utimbuf); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void utimes_adjust_read_pointers(struct utimes_req *utimes_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) utimes_req) + sizeof(struct utimes_req);
   
  if(utimes_req->filename != NULL) {
    utimes_req->filename = var_data;
    var_data += (strlen(utimes_req->filename) + 1); 
  }
   
}
     
  /* Adjusts the read pointers of the request, the space pointed by them
   * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void write_adjust_read_pointers(struct write_req *write_req) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) write_req) + sizeof(struct write_req);
   
  if(write_req->buf != NULL) {
    write_req->buf = var_data;
    var_data += write_req->count; 
  }
   
}
  
# if 0
/* I need also of the resp structure because the space for the buffer that need to be
 * send back are allocated after it. */
static void recvmsg_adjust_read_pointers(struct recvmsg_req *recvmsg_req) {
  struct msghdr *msg;
  int i;
  void *var_data;
  msg = &(recvmsg_req->msg);

  /* "var_data" points to the next data to read */
  printf("msg = %p\n", msg);
  var_data = ((void *) recvmsg_req) + sizeof(struct recvmsg_req);
  printf("var_data: begin = %p\n", var_data);
  if(msg->msg_name != NULL) {
    msg->msg_name = var_data;
    var_data += msg->msg_namelen;
  }
  printf("var_data: after msg_name = %p\n", var_data);
  
  if(msg->msg_iov != NULL) {
    msg->msg_iov = calloc(msg->msg_iovlen, sizeof(struct iovec)); /*FIXME: maybe a control on the result of calloc? */
    for(i = 0; i < msg->msg_iovlen; i++) {
      (msg->msg_iov[i]).iov_len = *((size_t *)var_data);
      (msg->msg_iov[i]).iov_base = malloc((msg->msg_iov[i]).iov_len);
      var_data += sizeof((msg->msg_iov[i]).iov_len);
    }
  }
  printf("var_data: after msg_iov = %p\n", var_data);

  if(msg->msg_control != NULL)
    msg->msg_control = var_data;
  printf("var_data: after msg_control = %p\n", var_data);
}
#endif

/* Adjusts the read pointers of the request, the space pointed by them
 * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void ioctl_adjust_read_pointers(struct ioctl_req *ioctl_req, u_int32_t size_type) {
  void *var_data;

  if(ioctl_req->arg != NULL && (size_type & IOCTL_R)) {
    /* "var_data" points to the next data to read */
    var_data = ((void *) ioctl_req) + sizeof(struct ioctl_req);
    RSC_DEBUG(RSCD_REQ_RESP, "ioctl_req->arg = %p", var_data);
    ioctl_req->arg = var_data;
  }
}

/* Adjusts the read pointers of the request, the space pointed by them
 * is stored in the request (in fact these informations are sent by the client). */
#ifndef RSCDEBUG
static 
#endif
void fcntl_adjust_read_pointers(struct fcntl_req *fcntl_req) {
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK_R) {
    void *var_data;
    /* "var_data" points to the next data to read */
    var_data = ((void *) fcntl_req) + sizeof(struct fcntl_req);
   
    RSC_DEBUG(RSCD_REQ_RESP, "fcntl_req->third.lock = %p", var_data);
    if(fcntl_req->third.lock != NULL)
      fcntl_req->third.lock = var_data;
  }
}
/**************************************************************************/
/***  ADJUST WRITE POINTERS                                             ***/
/**************************************************************************/
   
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void _llseek_adjust_write_pointers(struct _llseek_req *_llseek_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(_llseek_req->result != NULL) {
    if(my_arch == client_arch) {
 
      _llseek_req->result = var_data;
      var_data += sizeof(loff_t); 
    } else {
  
      _llseek_req->result = calloc(1, aconv_loff_t_size(my_arch, client_arch));
      assert(_llseek_req->result != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "_llseek_req->result = %p", var_data);
  if(_llseek_req->result != NULL) {
   
    _llseek_req->result = var_data;
    var_data += sizeof(loff_t); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void accept_adjust_write_pointers(struct accept_req *accept_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(accept_req->addrlen != NULL) {
    if(my_arch == client_arch) {
  
    /* 'accept_req->addrlen' contains the old value */
    memcpy(var_data, accept_req->addrlen, sizeof(socklen_t));
 
      accept_req->addrlen = var_data;
      var_data += sizeof(socklen_t); 
    } else {
    }
      
  }
  if(accept_req->addr != NULL) {
    if(my_arch == client_arch) {
 
      accept_req->addr = var_data;
      var_data += *(accept_req->addrlen); 
    } else {
  
      accept_req->addr = calloc(1, aconv_struct_sockaddr_size(my_arch, client_arch));
      assert(accept_req->addr != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "accept_req->addrlen = %p", var_data);
  if(accept_req->addrlen != NULL) {
    
    /* 'accept_req->addrlen' contains the old value */
    memcpy(var_data, accept_req->addrlen, sizeof(socklen_t));
   
    accept_req->addrlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "accept_req->addr = %p", var_data);
  if(accept_req->addr != NULL) {
   
    accept_req->addr = var_data;
    var_data += *(accept_req->addrlen); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void adjtimex_adjust_write_pointers(struct adjtimex_req *adjtimex_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(adjtimex_req->buf != NULL) {
    if(my_arch == client_arch) {
  
    /* 'adjtimex_req->buf' contains the old value */
    memcpy(var_data, adjtimex_req->buf, sizeof(struct timex));
 
      adjtimex_req->buf = var_data;
      var_data += sizeof(struct timex); 
    } else {
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "adjtimex_req->buf = %p", var_data);
  if(adjtimex_req->buf != NULL) {
    
    /* 'adjtimex_req->buf' contains the old value */
    memcpy(var_data, adjtimex_req->buf, sizeof(struct timex));
   
    adjtimex_req->buf = var_data;
    var_data += sizeof(struct timex); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void clock_getres_adjust_write_pointers(struct clock_getres_req *clock_getres_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(clock_getres_req->res != NULL) {
    if(my_arch == client_arch) {
 
      clock_getres_req->res = var_data;
      var_data += sizeof(struct timespec); 
    } else {
  
      clock_getres_req->res = calloc(1, aconv_struct_timespec_size(my_arch, client_arch));
      assert(clock_getres_req->res != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "clock_getres_req->res = %p", var_data);
  if(clock_getres_req->res != NULL) {
   
    clock_getres_req->res = var_data;
    var_data += sizeof(struct timespec); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void clock_gettime_adjust_write_pointers(struct clock_gettime_req *clock_gettime_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(clock_gettime_req->tp != NULL) {
    if(my_arch == client_arch) {
 
      clock_gettime_req->tp = var_data;
      var_data += sizeof(struct timespec); 
    } else {
  
      clock_gettime_req->tp = calloc(1, aconv_struct_timespec_size(my_arch, client_arch));
      assert(clock_gettime_req->tp != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "clock_gettime_req->tp = %p", var_data);
  if(clock_gettime_req->tp != NULL) {
   
    clock_gettime_req->tp = var_data;
    var_data += sizeof(struct timespec); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void fgetxattr_adjust_write_pointers(struct fgetxattr_req *fgetxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(fgetxattr_req->value != NULL) {
    if(my_arch == client_arch) {
 
      fgetxattr_req->value = var_data;
      var_data += fgetxattr_req->size; 
    } else {
  
      fgetxattr_req->value = calloc(1, aconv_bytes_size(fgetxattr_req->size, my_arch, client_arch));
      assert(fgetxattr_req->value != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "fgetxattr_req->value = %p", var_data);
  if(fgetxattr_req->value != NULL) {
   
    fgetxattr_req->value = var_data;
    var_data += fgetxattr_req->size; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void fstat64_adjust_write_pointers(struct fstat64_req *fstat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(fstat64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      fstat64_req->buf = var_data;
      var_data += sizeof(struct stat64); 
    } else {
  
      fstat64_req->buf = calloc(1, aconv_struct_stat64_size(my_arch, client_arch));
      assert(fstat64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "fstat64_req->buf = %p", var_data);
  if(fstat64_req->buf != NULL) {
   
    fstat64_req->buf = var_data;
    var_data += sizeof(struct stat64); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void fstatfs64_adjust_write_pointers(struct fstatfs64_req *fstatfs64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(fstatfs64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      fstatfs64_req->buf = var_data;
      var_data += sizeof(struct statfs64); 
    } else {
  
      fstatfs64_req->buf = calloc(1, aconv_struct_statfs64_size(my_arch, client_arch));
      assert(fstatfs64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "fstatfs64_req->buf = %p", var_data);
  if(fstatfs64_req->buf != NULL) {
   
    fstatfs64_req->buf = var_data;
    var_data += sizeof(struct statfs64); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void getdents64_adjust_write_pointers(struct getdents64_req *getdents64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(getdents64_req->dirp != NULL) {
    if(my_arch == client_arch) {
 
      getdents64_req->dirp = var_data;
      var_data += getdents64_req->count; 
    } else {
  
      getdents64_req->dirp = calloc(1, aconv_struct_dirent64_size(my_arch, client_arch));
      assert(getdents64_req->dirp != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "getdents64_req->dirp = %p", var_data);
  if(getdents64_req->dirp != NULL) {
   
    getdents64_req->dirp = var_data;
    var_data += getdents64_req->count; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void getpeername_adjust_write_pointers(struct getpeername_req *getpeername_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(getpeername_req->namelen != NULL) {
    if(my_arch == client_arch) {
  
    /* 'getpeername_req->namelen' contains the old value */
    memcpy(var_data, getpeername_req->namelen, sizeof(socklen_t));
 
      getpeername_req->namelen = var_data;
      var_data += sizeof(socklen_t); 
    } else {
    }
      
  }
  if(getpeername_req->name != NULL) {
    if(my_arch == client_arch) {
 
      getpeername_req->name = var_data;
      var_data += *(getpeername_req->namelen); 
    } else {
  
      getpeername_req->name = calloc(1, aconv_struct_sockaddr_size(my_arch, client_arch));
      assert(getpeername_req->name != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "getpeername_req->namelen = %p", var_data);
  if(getpeername_req->namelen != NULL) {
    
    /* 'getpeername_req->namelen' contains the old value */
    memcpy(var_data, getpeername_req->namelen, sizeof(socklen_t));
   
    getpeername_req->namelen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "getpeername_req->name = %p", var_data);
  if(getpeername_req->name != NULL) {
   
    getpeername_req->name = var_data;
    var_data += *(getpeername_req->namelen); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void getsockname_adjust_write_pointers(struct getsockname_req *getsockname_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(getsockname_req->namelen != NULL) {
    if(my_arch == client_arch) {
  
    /* 'getsockname_req->namelen' contains the old value */
    memcpy(var_data, getsockname_req->namelen, sizeof(socklen_t));
 
      getsockname_req->namelen = var_data;
      var_data += sizeof(socklen_t); 
    } else {
    }
      
  }
  if(getsockname_req->name != NULL) {
    if(my_arch == client_arch) {
 
      getsockname_req->name = var_data;
      var_data += *(getsockname_req->namelen); 
    } else {
  
      getsockname_req->name = calloc(1, aconv_struct_sockaddr_size(my_arch, client_arch));
      assert(getsockname_req->name != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "getsockname_req->namelen = %p", var_data);
  if(getsockname_req->namelen != NULL) {
    
    /* 'getsockname_req->namelen' contains the old value */
    memcpy(var_data, getsockname_req->namelen, sizeof(socklen_t));
   
    getsockname_req->namelen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "getsockname_req->name = %p", var_data);
  if(getsockname_req->name != NULL) {
   
    getsockname_req->name = var_data;
    var_data += *(getsockname_req->namelen); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void getsockopt_adjust_write_pointers(struct getsockopt_req *getsockopt_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(getsockopt_req->optlen != NULL) {
    if(my_arch == client_arch) {
  
    /* 'getsockopt_req->optlen' contains the old value */
    memcpy(var_data, getsockopt_req->optlen, sizeof(socklen_t));
 
      getsockopt_req->optlen = var_data;
      var_data += sizeof(socklen_t); 
    } else {
    }
      
  }
  if(getsockopt_req->optval != NULL) {
    if(my_arch == client_arch) {
 
      getsockopt_req->optval = var_data;
      var_data += *(getsockopt_req->optlen); 
    } else {
  
      getsockopt_req->optval = calloc(1, aconv_bytes_size(*(getsockopt_req->optlen), my_arch, client_arch));
      assert(getsockopt_req->optval != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "getsockopt_req->optlen = %p", var_data);
  if(getsockopt_req->optlen != NULL) {
    
    /* 'getsockopt_req->optlen' contains the old value */
    memcpy(var_data, getsockopt_req->optlen, sizeof(socklen_t));
   
    getsockopt_req->optlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "getsockopt_req->optval = %p", var_data);
  if(getsockopt_req->optval != NULL) {
   
    getsockopt_req->optval = var_data;
    var_data += *(getsockopt_req->optlen); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void gettimeofday_adjust_write_pointers(struct gettimeofday_req *gettimeofday_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(gettimeofday_req->tv != NULL) {
    if(my_arch == client_arch) {
 
      gettimeofday_req->tv = var_data;
      var_data += sizeof(struct timeval); 
    } else {
  
      gettimeofday_req->tv = calloc(1, aconv_struct_timeval_size(my_arch, client_arch));
      assert(gettimeofday_req->tv != NULL);
    }
      
  }
  if(gettimeofday_req->tz != NULL) {
    if(my_arch == client_arch) {
 
      gettimeofday_req->tz = var_data;
      var_data += sizeof(struct timezone); 
    } else {
  
      gettimeofday_req->tz = calloc(1, aconv_struct_timezone_size(my_arch, client_arch));
      assert(gettimeofday_req->tz != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "gettimeofday_req->tv = %p", var_data);
  if(gettimeofday_req->tv != NULL) {
   
    gettimeofday_req->tv = var_data;
    var_data += sizeof(struct timeval); 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "gettimeofday_req->tz = %p", var_data);
  if(gettimeofday_req->tz != NULL) {
   
    gettimeofday_req->tz = var_data;
    var_data += sizeof(struct timezone); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void getxattr_adjust_write_pointers(struct getxattr_req *getxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(getxattr_req->value != NULL) {
    if(my_arch == client_arch) {
 
      getxattr_req->value = var_data;
      var_data += getxattr_req->size; 
    } else {
  
      getxattr_req->value = calloc(1, aconv_bytes_size(getxattr_req->size, my_arch, client_arch));
      assert(getxattr_req->value != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "getxattr_req->value = %p", var_data);
  if(getxattr_req->value != NULL) {
   
    getxattr_req->value = var_data;
    var_data += getxattr_req->size; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void lgetxattr_adjust_write_pointers(struct lgetxattr_req *lgetxattr_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(lgetxattr_req->value != NULL) {
    if(my_arch == client_arch) {
 
      lgetxattr_req->value = var_data;
      var_data += lgetxattr_req->size; 
    } else {
  
      lgetxattr_req->value = calloc(1, aconv_bytes_size(lgetxattr_req->size, my_arch, client_arch));
      assert(lgetxattr_req->value != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "lgetxattr_req->value = %p", var_data);
  if(lgetxattr_req->value != NULL) {
   
    lgetxattr_req->value = var_data;
    var_data += lgetxattr_req->size; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void lstat64_adjust_write_pointers(struct lstat64_req *lstat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(lstat64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      lstat64_req->buf = var_data;
      var_data += sizeof(struct stat64); 
    } else {
  
      lstat64_req->buf = calloc(1, aconv_struct_stat64_size(my_arch, client_arch));
      assert(lstat64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "lstat64_req->buf = %p", var_data);
  if(lstat64_req->buf != NULL) {
   
    lstat64_req->buf = var_data;
    var_data += sizeof(struct stat64); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void pread64_adjust_write_pointers(struct pread64_req *pread64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(pread64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      pread64_req->buf = var_data;
      var_data += pread64_req->count; 
    } else {
  
      pread64_req->buf = calloc(1, aconv_bytes_size(pread64_req->count, my_arch, client_arch));
      assert(pread64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "pread64_req->buf = %p", var_data);
  if(pread64_req->buf != NULL) {
   
    pread64_req->buf = var_data;
    var_data += pread64_req->count; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void read_adjust_write_pointers(struct read_req *read_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(read_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      read_req->buf = var_data;
      var_data += read_req->count; 
    } else {
  
      read_req->buf = calloc(1, aconv_bytes_size(read_req->count, my_arch, client_arch));
      assert(read_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "read_req->buf = %p", var_data);
  if(read_req->buf != NULL) {
   
    read_req->buf = var_data;
    var_data += read_req->count; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void readlink_adjust_write_pointers(struct readlink_req *readlink_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(readlink_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      readlink_req->buf = var_data;
      var_data += readlink_req->bufsiz; 
    } else {
  
      readlink_req->buf = calloc(1, readlink_req->bufsiz);
      assert(readlink_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "readlink_req->buf = %p", var_data);
  if(readlink_req->buf != NULL) {
   
    readlink_req->buf = var_data;
    var_data += readlink_req->bufsiz; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void recv_adjust_write_pointers(struct recv_req *recv_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(recv_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      recv_req->buf = var_data;
      var_data += recv_req->len; 
    } else {
  
      recv_req->buf = calloc(1, aconv_bytes_size(recv_req->len, my_arch, client_arch));
      assert(recv_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "recv_req->buf = %p", var_data);
  if(recv_req->buf != NULL) {
   
    recv_req->buf = var_data;
    var_data += recv_req->len; 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void recvfrom_adjust_write_pointers(struct recvfrom_req *recvfrom_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(recvfrom_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      recvfrom_req->buf = var_data;
      var_data += recvfrom_req->len; 
    } else {
  
      recvfrom_req->buf = calloc(1, aconv_bytes_size(recvfrom_req->len, my_arch, client_arch));
      assert(recvfrom_req->buf != NULL);
    }
      
  }
  if(recvfrom_req->fromlen != NULL) {
    if(my_arch == client_arch) {
  
    /* 'recvfrom_req->fromlen' contains the old value */
    memcpy(var_data, recvfrom_req->fromlen, sizeof(socklen_t));
 
      recvfrom_req->fromlen = var_data;
      var_data += sizeof(socklen_t); 
    } else {
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "recvfrom_req->buf = %p", var_data);
  if(recvfrom_req->buf != NULL) {
   
    recvfrom_req->buf = var_data;
    var_data += recvfrom_req->len; 
  }
   
  RSC_DEBUG(RSCD_REQ_RESP, "recvfrom_req->fromlen = %p", var_data);
  if(recvfrom_req->fromlen != NULL) {
    
    /* 'recvfrom_req->fromlen' contains the old value */
    memcpy(var_data, recvfrom_req->fromlen, sizeof(socklen_t));
   
    recvfrom_req->fromlen = var_data;
    var_data += sizeof(socklen_t); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void stat64_adjust_write_pointers(struct stat64_req *stat64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(stat64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      stat64_req->buf = var_data;
      var_data += sizeof(struct stat64); 
    } else {
  
      stat64_req->buf = calloc(1, aconv_struct_stat64_size(my_arch, client_arch));
      assert(stat64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "stat64_req->buf = %p", var_data);
  if(stat64_req->buf != NULL) {
   
    stat64_req->buf = var_data;
    var_data += sizeof(struct stat64); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void statfs64_adjust_write_pointers(struct statfs64_req *statfs64_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(statfs64_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      statfs64_req->buf = var_data;
      var_data += sizeof(struct statfs64); 
    } else {
  
      statfs64_req->buf = calloc(1, aconv_struct_statfs64_size(my_arch, client_arch));
      assert(statfs64_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "statfs64_req->buf = %p", var_data);
  if(statfs64_req->buf != NULL) {
   
    statfs64_req->buf = var_data;
    var_data += sizeof(struct statfs64); 
  }
   
#endif
}
     
  /* Adjusts the write pointers of the request. If client and server architecture
   * are equal, the space is stored inside the response, otherwise new space
   * is malloced and after the execution of the syscall will be copied inside the
   * response. 
   * The value-result arguments have been already adjusted by *_adjust_read_pointers()
   * function. */
#ifndef RSCDEBUG
static 
#endif
void uname_adjust_write_pointers(struct uname_req *uname_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;

  /* "var_data" points to the next data to read */
  var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
  if(uname_req->buf != NULL) {
    if(my_arch == client_arch) {
 
      uname_req->buf = var_data;
      var_data += sizeof(struct utsname); 
    } else {
  
      uname_req->buf = calloc(1, aconv_struct_utsname_size(my_arch, client_arch));
      assert(uname_req->buf != NULL);
    }
      
  }
 
#if 0
   
  RSC_DEBUG(RSCD_REQ_RESP, "uname_req->buf = %p", var_data);
  if(uname_req->buf != NULL) {
   
    uname_req->buf = var_data;
    var_data += sizeof(struct utsname); 
  }
   
#endif
}
  
/* Adjusts the write pointers of the request, the space pointed by them
 * is stored in the response (in fact these informations are sent back to the client). 
 * Note: read/write pointers are sent by the client and have to be sent back to it after
 * the system call, this kind of arguments are usually called "value-result". So, for
 * these arguments, their content is copied from the request to the response, in this
 * way when the syscall change it, the new value resides already in the response. */
#ifndef RSCDEBUG
static 
#endif
void ioctl_adjust_write_pointers(struct ioctl_req *ioctl_req, struct sys_resp_header *resp_header, int resp_size, u_int32_t size_type, enum arch client_arch) {
  void *var_data;

  if(ioctl_req->arg != NULL && (size_type & IOCTL_W)) {
    var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
   
    RSC_DEBUG(RSCD_REQ_RESP, "ioctl_req->arg = %p", var_data);
    /* if 'ioctl_req->arg' is also a read pointer, I need to copy its content */
    if(size_type & IOCTL_R)
      memcpy(var_data, ioctl_req->arg, (size_type & IOCTL_LENMASK));
   
    ioctl_req->arg = var_data;
  }
   
}

/* Adjusts the write pointers of the request, the space pointed by them
 * is stored in the response (in fact these informations are sent back to the client). 
 * Note: read/write pointers are sent by the client and have to be sent back to it after
 * the system call, this kind of arguments are usually called "value-result". So, for
 * these arguments, their content is copied from the request to the response, in this
 * way when the syscall change it, the new value resides already in the response. */
#ifndef RSCDEBUG
static 
#endif
void fcntl_adjust_write_pointers(struct fcntl_req *fcntl_req, struct sys_resp_header *resp_header, int resp_size, enum arch client_arch) {
  void *var_data;
  if( (fcntl_req->cmd_type & FCNTL_3RD_FLOCK_W) && (fcntl_req->third.lock != NULL)) {
    /* "var_data" points to the next data to read */
    var_data = ((void *) resp_header) + sizeof(struct sys_resp_header);
    RSC_DEBUG(RSCD_REQ_RESP, "fcntl_req->third.lock = %p", var_data);
    /* 'fcntl_req->third.lock' contains the old value */
    memcpy(var_data, fcntl_req->third.lock, sizeof(struct flock));
    fcntl_req->third.lock = var_data;
  }
}



/**************************************************************************/
/***  EXECUTION FUNCTIONS                                               ***/
/**************************************************************************/
struct sys_resp_header *rscs_pre__llseek_exec(void *req, enum arch client_arch) {
  struct _llseek_req *_llseek_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  _llseek_req = (struct _llseek_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(_llseek_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(_llseek_req),
      rsc2str(_llseek_req->req_rsc_const), _llseek_req->req_rsc_const,
      _llseek_req->req_type, _llseek_req->req_type, 
      _llseek_req->req_size, _llseek_req->req_size);

  if(_llseek_req->req_size < sizeof(struct _llseek_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %u (0x%lX); offset_high = %lu (0x%lX); offset_low = %lu (0x%lX); result = %p (0x%lX); whence = %u (0x%lX)", _llseek_req->fd, _llseek_req->fd, _llseek_req->offset_high, _llseek_req->offset_high, _llseek_req->offset_low, _llseek_req->offset_low, _llseek_req->result, _llseek_req->result, _llseek_req->whence, _llseek_req->whence);

  
  resp_size = sizeof(struct sys_resp_header);
  if(_llseek_req->result != NULL) {
    resp_size += aconv_loff_t_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  _llseek_adjust_write_pointers(_llseek_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, _llseek_req, _llseek_req->req_size);

  /* resp_header->resp_type = _llseek_req->req_type; */
  resp_header->resp_rsc_const = _llseek_req->req_rsc_const;
  return resp_header;
}

int rscs_exec__llseek(void  *request) {
  int ret;
  struct _llseek_req *req = (struct _llseek_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->offset_high, req->offset_low, req->result, req->whence);
  
  return ret;
}

struct sys_resp_header *rscs_post__llseek_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct _llseek_req *_llseek_req = (struct _llseek_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_loff_t(_llseek_req->result, my_arch, client_arch, mem);
    mem += aconv_loff_t_size(my_arch, client_arch);
    free(_llseek_req->result);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_accept_exec(void *req, enum arch client_arch) {
  struct accept_req *accept_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  accept_req = (struct accept_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(accept_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(accept_req),
      rsc2str(accept_req->req_rsc_const), accept_req->req_rsc_const,
      accept_req->req_type, accept_req->req_type, 
      accept_req->req_size, accept_req->req_size);

  if(accept_req->req_size < sizeof(struct accept_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: sockfd = %ld (0x%lX); addr = %p (0x%lX); addrlen = %p (0x%lX)", accept_req->sockfd, accept_req->sockfd, accept_req->addr, accept_req->addr, accept_req->addrlen, accept_req->addrlen);

   
  /* Adjusts the read pointers of the request */
  accept_adjust_read_pointers(accept_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(accept_req->addrlen != NULL) {
    resp_size += aconv_socklen_t_size(my_arch, client_arch); 
  }
  if(accept_req->addr != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'addrlen' argument. */
    /* The client can have changed the value of socklen_t *addrlen if it was less than
     * the size of addr into server arch. So If socklen_t *addrlen is equal
     * to this value I need to change it to the right value on client arch. */
    if(*(accept_req->addrlen) == aconv_struct_sockaddr_size(client_arch, my_arch)) {
      resp_size += aconv_struct_sockaddr_size(my_arch, client_arch);
    } else {
      resp_size += *(accept_req->addrlen); 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  accept_adjust_write_pointers(accept_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, accept_req, accept_req->req_size);

  /* resp_header->resp_type = accept_req->req_type; */
  resp_header->resp_rsc_const = accept_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_accept(void  *request) {
  int ret;
  struct accept_req *req = (struct accept_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->sockfd, req->addr, req->addrlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->sockfd),
			(unsigned long)(req->addr),
			(unsigned long)(req->addrlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_accept_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct accept_req *accept_req = (struct accept_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_socklen_t(accept_req->addrlen, my_arch, client_arch, mem);
    mem += aconv_socklen_t_size(my_arch, client_arch);
    aconv_struct_sockaddr(accept_req->addr, my_arch, client_arch, mem);
    mem += aconv_struct_sockaddr_size(my_arch, client_arch);
    free(accept_req->addr);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_access_exec(void *req, enum arch client_arch) {
  struct access_req *access_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  access_req = (struct access_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(access_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(access_req),
      rsc2str(access_req->req_rsc_const), access_req->req_rsc_const,
      access_req->req_type, access_req->req_type, 
      access_req->req_size, access_req->req_size);

  if(access_req->req_size < sizeof(struct access_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: pathname = %p (0x%lX); mode = %ld (0x%lX)", access_req->pathname, access_req->pathname, access_req->mode, access_req->mode);

   
  /* Adjusts the read pointers of the request */
  access_adjust_read_pointers(access_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, access_req, access_req->req_size);

  /* resp_header->resp_type = access_req->req_type; */
  resp_header->resp_rsc_const = access_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_access(void  *request) {
  int ret;
  struct access_req *req = (struct access_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->pathname, req->mode);
  
  return ret;
}

struct sys_resp_header *rscs_post_access_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_adjtimex_exec(void *req, enum arch client_arch) {
  struct adjtimex_req *adjtimex_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  adjtimex_req = (struct adjtimex_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(adjtimex_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(adjtimex_req),
      rsc2str(adjtimex_req->req_rsc_const), adjtimex_req->req_rsc_const,
      adjtimex_req->req_type, adjtimex_req->req_type, 
      adjtimex_req->req_size, adjtimex_req->req_size);

  if(adjtimex_req->req_size < sizeof(struct adjtimex_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: buf = %p (0x%lX)", adjtimex_req->buf, adjtimex_req->buf);

   
  /* Adjusts the read pointers of the request */
  adjtimex_adjust_read_pointers(adjtimex_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(adjtimex_req->buf != NULL) {
    resp_size += aconv_struct_timex_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  adjtimex_adjust_write_pointers(adjtimex_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, adjtimex_req, adjtimex_req->req_size);

  /* resp_header->resp_type = adjtimex_req->req_type; */
  resp_header->resp_rsc_const = adjtimex_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_adjtimex(void  *request) {
  int ret;
  struct adjtimex_req *req = (struct adjtimex_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_adjtimex_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct adjtimex_req *adjtimex_req = (struct adjtimex_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_timex(adjtimex_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_timex_size(my_arch, client_arch);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_bind_exec(void *req, enum arch client_arch) {
  struct bind_req *bind_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  bind_req = (struct bind_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(bind_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(bind_req),
      rsc2str(bind_req->req_rsc_const), bind_req->req_rsc_const,
      bind_req->req_type, bind_req->req_type, 
      bind_req->req_size, bind_req->req_size);

  if(bind_req->req_size < sizeof(struct bind_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: sockfd = %ld (0x%lX); my_addr = %p (0x%lX); addrlen = %ld (0x%lX)", bind_req->sockfd, bind_req->sockfd, bind_req->my_addr, bind_req->my_addr, bind_req->addrlen, bind_req->addrlen);

   
  /* Adjusts the read pointers of the request */
  bind_adjust_read_pointers(bind_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, bind_req, bind_req->req_size);

  /* resp_header->resp_type = bind_req->req_type; */
  resp_header->resp_rsc_const = bind_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_bind(void  *request) {
  int ret;
  struct bind_req *req = (struct bind_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->sockfd, req->my_addr, req->addrlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->sockfd),
			(unsigned long)(req->my_addr),
			(unsigned long)(req->addrlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_bind_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_chdir_exec(void *req, enum arch client_arch) {
  struct chdir_req *chdir_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  chdir_req = (struct chdir_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(chdir_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(chdir_req),
      rsc2str(chdir_req->req_rsc_const), chdir_req->req_rsc_const,
      chdir_req->req_type, chdir_req->req_type, 
      chdir_req->req_size, chdir_req->req_size);

  if(chdir_req->req_size < sizeof(struct chdir_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX)", chdir_req->path, chdir_req->path);

   
  /* Adjusts the read pointers of the request */
  chdir_adjust_read_pointers(chdir_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, chdir_req, chdir_req->req_size);

  /* resp_header->resp_type = chdir_req->req_type; */
  resp_header->resp_rsc_const = chdir_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_chdir(void  *request) {
  int ret;
  struct chdir_req *req = (struct chdir_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path);
  
  return ret;
}

struct sys_resp_header *rscs_post_chdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_chmod_exec(void *req, enum arch client_arch) {
  struct chmod_req *chmod_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  chmod_req = (struct chmod_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(chmod_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(chmod_req),
      rsc2str(chmod_req->req_rsc_const), chmod_req->req_rsc_const,
      chmod_req->req_type, chmod_req->req_type, 
      chmod_req->req_size, chmod_req->req_size);

  if(chmod_req->req_size < sizeof(struct chmod_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); mode = %ld (0x%lX)", chmod_req->path, chmod_req->path, chmod_req->mode, chmod_req->mode);

   
  /* Adjusts the read pointers of the request */
  chmod_adjust_read_pointers(chmod_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, chmod_req, chmod_req->req_size);

  /* resp_header->resp_type = chmod_req->req_type; */
  resp_header->resp_rsc_const = chmod_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_chmod(void  *request) {
  int ret;
  struct chmod_req *req = (struct chmod_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->mode);
  
  return ret;
}

struct sys_resp_header *rscs_post_chmod_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_chown_exec(void *req, enum arch client_arch) {
  struct chown_req *chown_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  chown_req = (struct chown_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(chown_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(chown_req),
      rsc2str(chown_req->req_rsc_const), chown_req->req_rsc_const,
      chown_req->req_type, chown_req->req_type, 
      chown_req->req_size, chown_req->req_size);

  if(chown_req->req_size < sizeof(struct chown_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", chown_req->path, chown_req->path, chown_req->owner, chown_req->owner, chown_req->group, chown_req->group);

   
  /* Adjusts the read pointers of the request */
  chown_adjust_read_pointers(chown_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, chown_req, chown_req->req_size);

  /* resp_header->resp_type = chown_req->req_type; */
  resp_header->resp_rsc_const = chown_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_chown(void  *request) {
  int ret;
  struct chown_req *req = (struct chown_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_chown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_chown32_exec(void *req, enum arch client_arch) {
  struct chown32_req *chown32_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  chown32_req = (struct chown32_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(chown32_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(chown32_req),
      rsc2str(chown32_req->req_rsc_const), chown32_req->req_rsc_const,
      chown32_req->req_type, chown32_req->req_type, 
      chown32_req->req_size, chown32_req->req_size);

  if(chown32_req->req_size < sizeof(struct chown32_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", chown32_req->path, chown32_req->path, chown32_req->owner, chown32_req->owner, chown32_req->group, chown32_req->group);

   
  /* Adjusts the read pointers of the request */
  chown32_adjust_read_pointers(chown32_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, chown32_req, chown32_req->req_size);

  /* resp_header->resp_type = chown32_req->req_type; */
  resp_header->resp_rsc_const = chown32_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_chown32(void  *request) {
  int ret;
  struct chown32_req *req = (struct chown32_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_chown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_clock_getres_exec(void *req, enum arch client_arch) {
  struct clock_getres_req *clock_getres_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  clock_getres_req = (struct clock_getres_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(clock_getres_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(clock_getres_req),
      rsc2str(clock_getres_req->req_rsc_const), clock_getres_req->req_rsc_const,
      clock_getres_req->req_type, clock_getres_req->req_type, 
      clock_getres_req->req_size, clock_getres_req->req_size);

  if(clock_getres_req->req_size < sizeof(struct clock_getres_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: clk_id = %ld (0x%lX); res = %p (0x%lX)", clock_getres_req->clk_id, clock_getres_req->clk_id, clock_getres_req->res, clock_getres_req->res);

  
  resp_size = sizeof(struct sys_resp_header);
  if(clock_getres_req->res != NULL) {
    resp_size += aconv_struct_timespec_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  clock_getres_adjust_write_pointers(clock_getres_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, clock_getres_req, clock_getres_req->req_size);

  /* resp_header->resp_type = clock_getres_req->req_type; */
  resp_header->resp_rsc_const = clock_getres_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_clock_getres(void  *request) {
  int ret;
  struct clock_getres_req *req = (struct clock_getres_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->clk_id, req->res);
  
  return ret;
}

struct sys_resp_header *rscs_post_clock_getres_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct clock_getres_req *clock_getres_req = (struct clock_getres_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_timespec(clock_getres_req->res, my_arch, client_arch, mem);
    mem += aconv_struct_timespec_size(my_arch, client_arch);
    free(clock_getres_req->res);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_clock_gettime_exec(void *req, enum arch client_arch) {
  struct clock_gettime_req *clock_gettime_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  clock_gettime_req = (struct clock_gettime_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(clock_gettime_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(clock_gettime_req),
      rsc2str(clock_gettime_req->req_rsc_const), clock_gettime_req->req_rsc_const,
      clock_gettime_req->req_type, clock_gettime_req->req_type, 
      clock_gettime_req->req_size, clock_gettime_req->req_size);

  if(clock_gettime_req->req_size < sizeof(struct clock_gettime_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: clk_id = %ld (0x%lX); tp = %p (0x%lX)", clock_gettime_req->clk_id, clock_gettime_req->clk_id, clock_gettime_req->tp, clock_gettime_req->tp);

  
  resp_size = sizeof(struct sys_resp_header);
  if(clock_gettime_req->tp != NULL) {
    resp_size += aconv_struct_timespec_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  clock_gettime_adjust_write_pointers(clock_gettime_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, clock_gettime_req, clock_gettime_req->req_size);

  /* resp_header->resp_type = clock_gettime_req->req_type; */
  resp_header->resp_rsc_const = clock_gettime_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_clock_gettime(void  *request) {
  int ret;
  struct clock_gettime_req *req = (struct clock_gettime_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->clk_id, req->tp);
  
  return ret;
}

struct sys_resp_header *rscs_post_clock_gettime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct clock_gettime_req *clock_gettime_req = (struct clock_gettime_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_timespec(clock_gettime_req->tp, my_arch, client_arch, mem);
    mem += aconv_struct_timespec_size(my_arch, client_arch);
    free(clock_gettime_req->tp);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_clock_settime_exec(void *req, enum arch client_arch) {
  struct clock_settime_req *clock_settime_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  clock_settime_req = (struct clock_settime_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(clock_settime_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(clock_settime_req),
      rsc2str(clock_settime_req->req_rsc_const), clock_settime_req->req_rsc_const,
      clock_settime_req->req_type, clock_settime_req->req_type, 
      clock_settime_req->req_size, clock_settime_req->req_size);

  if(clock_settime_req->req_size < sizeof(struct clock_settime_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: clk_id = %ld (0x%lX); tp = %p (0x%lX)", clock_settime_req->clk_id, clock_settime_req->clk_id, clock_settime_req->tp, clock_settime_req->tp);

   
  /* Adjusts the read pointers of the request */
  clock_settime_adjust_read_pointers(clock_settime_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, clock_settime_req, clock_settime_req->req_size);

  /* resp_header->resp_type = clock_settime_req->req_type; */
  resp_header->resp_rsc_const = clock_settime_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_clock_settime(void  *request) {
  int ret;
  struct clock_settime_req *req = (struct clock_settime_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->clk_id, req->tp);
  
  return ret;
}

struct sys_resp_header *rscs_post_clock_settime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_close_exec(void *req, enum arch client_arch) {
  struct close_req *close_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  close_req = (struct close_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(close_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(close_req),
      rsc2str(close_req->req_rsc_const), close_req->req_rsc_const,
      close_req->req_type, close_req->req_type, 
      close_req->req_size, close_req->req_size);

  if(close_req->req_size < sizeof(struct close_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX)", close_req->fd, close_req->fd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, close_req, close_req->req_size);

  /* resp_header->resp_type = close_req->req_type; */
  resp_header->resp_rsc_const = close_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_close(void  *request) {
  int ret;
  struct close_req *req = (struct close_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd);
  
  return ret;
}

struct sys_resp_header *rscs_post_close_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_connect_exec(void *req, enum arch client_arch) {
  struct connect_req *connect_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  connect_req = (struct connect_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(connect_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(connect_req),
      rsc2str(connect_req->req_rsc_const), connect_req->req_rsc_const,
      connect_req->req_type, connect_req->req_type, 
      connect_req->req_size, connect_req->req_size);

  if(connect_req->req_size < sizeof(struct connect_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: sockfd = %ld (0x%lX); serv_addr = %p (0x%lX); addrlen = %ld (0x%lX)", connect_req->sockfd, connect_req->sockfd, connect_req->serv_addr, connect_req->serv_addr, connect_req->addrlen, connect_req->addrlen);

   
  /* Adjusts the read pointers of the request */
  connect_adjust_read_pointers(connect_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, connect_req, connect_req->req_size);

  /* resp_header->resp_type = connect_req->req_type; */
  resp_header->resp_rsc_const = connect_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_connect(void  *request) {
  int ret;
  struct connect_req *req = (struct connect_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->sockfd, req->serv_addr, req->addrlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->sockfd),
			(unsigned long)(req->serv_addr),
			(unsigned long)(req->addrlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_connect_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_dup_exec(void *req, enum arch client_arch) {
  struct dup_req *dup_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  dup_req = (struct dup_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(dup_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(dup_req),
      rsc2str(dup_req->req_rsc_const), dup_req->req_rsc_const,
      dup_req->req_type, dup_req->req_type, 
      dup_req->req_size, dup_req->req_size);

  if(dup_req->req_size < sizeof(struct dup_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: oldfd = %ld (0x%lX)", dup_req->oldfd, dup_req->oldfd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, dup_req, dup_req->req_size);

  /* resp_header->resp_type = dup_req->req_type; */
  resp_header->resp_rsc_const = dup_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_dup(void  *request) {
  int ret;
  struct dup_req *req = (struct dup_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->oldfd);
  
  return ret;
}

struct sys_resp_header *rscs_post_dup_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_dup2_exec(void *req, enum arch client_arch) {
  struct dup2_req *dup2_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  dup2_req = (struct dup2_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(dup2_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(dup2_req),
      rsc2str(dup2_req->req_rsc_const), dup2_req->req_rsc_const,
      dup2_req->req_type, dup2_req->req_type, 
      dup2_req->req_size, dup2_req->req_size);

  if(dup2_req->req_size < sizeof(struct dup2_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: oldfd = %ld (0x%lX); newfd = %ld (0x%lX)", dup2_req->oldfd, dup2_req->oldfd, dup2_req->newfd, dup2_req->newfd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, dup2_req, dup2_req->req_size);

  /* resp_header->resp_type = dup2_req->req_type; */
  resp_header->resp_rsc_const = dup2_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_dup2(void  *request) {
  int ret;
  struct dup2_req *req = (struct dup2_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->oldfd, req->newfd);
  
  return ret;
}

struct sys_resp_header *rscs_post_dup2_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fchdir_exec(void *req, enum arch client_arch) {
  struct fchdir_req *fchdir_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fchdir_req = (struct fchdir_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fchdir_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fchdir_req),
      rsc2str(fchdir_req->req_rsc_const), fchdir_req->req_rsc_const,
      fchdir_req->req_type, fchdir_req->req_type, 
      fchdir_req->req_size, fchdir_req->req_size);

  if(fchdir_req->req_size < sizeof(struct fchdir_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX)", fchdir_req->fd, fchdir_req->fd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fchdir_req, fchdir_req->req_size);

  /* resp_header->resp_type = fchdir_req->req_type; */
  resp_header->resp_rsc_const = fchdir_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fchdir(void  *request) {
  int ret;
  struct fchdir_req *req = (struct fchdir_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd);
  
  return ret;
}

struct sys_resp_header *rscs_post_fchdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fchmod_exec(void *req, enum arch client_arch) {
  struct fchmod_req *fchmod_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fchmod_req = (struct fchmod_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fchmod_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fchmod_req),
      rsc2str(fchmod_req->req_rsc_const), fchmod_req->req_rsc_const,
      fchmod_req->req_type, fchmod_req->req_type, 
      fchmod_req->req_size, fchmod_req->req_size);

  if(fchmod_req->req_size < sizeof(struct fchmod_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fildes = %ld (0x%lX); mode = %ld (0x%lX)", fchmod_req->fildes, fchmod_req->fildes, fchmod_req->mode, fchmod_req->mode);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fchmod_req, fchmod_req->req_size);

  /* resp_header->resp_type = fchmod_req->req_type; */
  resp_header->resp_rsc_const = fchmod_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fchmod(void  *request) {
  int ret;
  struct fchmod_req *req = (struct fchmod_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fildes, req->mode);
  
  return ret;
}

struct sys_resp_header *rscs_post_fchmod_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fchown_exec(void *req, enum arch client_arch) {
  struct fchown_req *fchown_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fchown_req = (struct fchown_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fchown_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fchown_req),
      rsc2str(fchown_req->req_rsc_const), fchown_req->req_rsc_const,
      fchown_req->req_type, fchown_req->req_type, 
      fchown_req->req_size, fchown_req->req_size);

  if(fchown_req->req_size < sizeof(struct fchown_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", fchown_req->fd, fchown_req->fd, fchown_req->owner, fchown_req->owner, fchown_req->group, fchown_req->group);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fchown_req, fchown_req->req_size);

  /* resp_header->resp_type = fchown_req->req_type; */
  resp_header->resp_rsc_const = fchown_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fchown(void  *request) {
  int ret;
  struct fchown_req *req = (struct fchown_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_fchown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fchown32_exec(void *req, enum arch client_arch) {
  struct fchown32_req *fchown32_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fchown32_req = (struct fchown32_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fchown32_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fchown32_req),
      rsc2str(fchown32_req->req_rsc_const), fchown32_req->req_rsc_const,
      fchown32_req->req_type, fchown32_req->req_type, 
      fchown32_req->req_size, fchown32_req->req_size);

  if(fchown32_req->req_size < sizeof(struct fchown32_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", fchown32_req->fd, fchown32_req->fd, fchown32_req->owner, fchown32_req->owner, fchown32_req->group, fchown32_req->group);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fchown32_req, fchown32_req->req_size);

  /* resp_header->resp_type = fchown32_req->req_type; */
  resp_header->resp_rsc_const = fchown32_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fchown32(void  *request) {
  int ret;
  struct fchown32_req *req = (struct fchown32_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_fchown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fdatasync_exec(void *req, enum arch client_arch) {
  struct fdatasync_req *fdatasync_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fdatasync_req = (struct fdatasync_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fdatasync_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fdatasync_req),
      rsc2str(fdatasync_req->req_rsc_const), fdatasync_req->req_rsc_const,
      fdatasync_req->req_type, fdatasync_req->req_type, 
      fdatasync_req->req_size, fdatasync_req->req_size);

  if(fdatasync_req->req_size < sizeof(struct fdatasync_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX)", fdatasync_req->fd, fdatasync_req->fd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fdatasync_req, fdatasync_req->req_size);

  /* resp_header->resp_type = fdatasync_req->req_type; */
  resp_header->resp_rsc_const = fdatasync_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fdatasync(void  *request) {
  int ret;
  struct fdatasync_req *req = (struct fdatasync_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd);
  
  return ret;
}

struct sys_resp_header *rscs_post_fdatasync_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fgetxattr_exec(void *req, enum arch client_arch) {
  struct fgetxattr_req *fgetxattr_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fgetxattr_req = (struct fgetxattr_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fgetxattr_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fgetxattr_req),
      rsc2str(fgetxattr_req->req_rsc_const), fgetxattr_req->req_rsc_const,
      fgetxattr_req->req_type, fgetxattr_req->req_type, 
      fgetxattr_req->req_size, fgetxattr_req->req_size);

  if(fgetxattr_req->req_size < sizeof(struct fgetxattr_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: filedes = %ld (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", fgetxattr_req->filedes, fgetxattr_req->filedes, fgetxattr_req->name, fgetxattr_req->name, fgetxattr_req->value, fgetxattr_req->value, fgetxattr_req->size, fgetxattr_req->size);

   
  /* Adjusts the read pointers of the request */
  fgetxattr_adjust_read_pointers(fgetxattr_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(fgetxattr_req->value != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'size' argument. */
    /* The client can have changed the value of size_t size if it was less than
     * the size of value into server arch. So If size_t size is equal
     * to this value I need to change it to the right value on client arch. */
    if(fgetxattr_req->size == aconv_bytes_size(fgetxattr_req->size, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(fgetxattr_req->size, my_arch, client_arch);
    } else {
      resp_size += fgetxattr_req->size; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  fgetxattr_adjust_write_pointers(fgetxattr_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, fgetxattr_req, fgetxattr_req->req_size);

  /* resp_header->resp_type = fgetxattr_req->req_type; */
  resp_header->resp_rsc_const = fgetxattr_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fgetxattr(void  *request) {
  int ret;
  struct fgetxattr_req *req = (struct fgetxattr_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->filedes, req->name, req->value, req->size);
  
  return ret;
}

struct sys_resp_header *rscs_post_fgetxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct fgetxattr_req *fgetxattr_req = (struct fgetxattr_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(fgetxattr_req->value, my_arch, client_arch, mem, fgetxattr_req->size);
    mem += aconv_bytes_size(fgetxattr_req->size, my_arch, client_arch);
    free(fgetxattr_req->value);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fstat64_exec(void *req, enum arch client_arch) {
  struct fstat64_req *fstat64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fstat64_req = (struct fstat64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fstat64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fstat64_req),
      rsc2str(fstat64_req->req_rsc_const), fstat64_req->req_rsc_const,
      fstat64_req->req_type, fstat64_req->req_type, 
      fstat64_req->req_size, fstat64_req->req_size);

  if(fstat64_req->req_size < sizeof(struct fstat64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: filedes = %ld (0x%lX); buf = %p (0x%lX)", fstat64_req->filedes, fstat64_req->filedes, fstat64_req->buf, fstat64_req->buf);

  
  resp_size = sizeof(struct sys_resp_header);
  if(fstat64_req->buf != NULL) {
    resp_size += aconv_struct_stat64_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  fstat64_adjust_write_pointers(fstat64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, fstat64_req, fstat64_req->req_size);

  /* resp_header->resp_type = fstat64_req->req_type; */
  resp_header->resp_rsc_const = fstat64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fstat64(void  *request) {
  int ret;
  struct fstat64_req *req = (struct fstat64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->filedes, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_fstat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct fstat64_req *fstat64_req = (struct fstat64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_stat64(fstat64_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_stat64_size(my_arch, client_arch);
    free(fstat64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fstatfs64_exec(void *req, enum arch client_arch) {
  struct fstatfs64_req *fstatfs64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fstatfs64_req = (struct fstatfs64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fstatfs64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fstatfs64_req),
      rsc2str(fstatfs64_req->req_rsc_const), fstatfs64_req->req_rsc_const,
      fstatfs64_req->req_type, fstatfs64_req->req_type, 
      fstatfs64_req->req_size, fstatfs64_req->req_size);

  if(fstatfs64_req->req_size < sizeof(struct fstatfs64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %u (0x%lX); buf = %p (0x%lX)", fstatfs64_req->fd, fstatfs64_req->fd, fstatfs64_req->buf, fstatfs64_req->buf);

  
  resp_size = sizeof(struct sys_resp_header);
  if(fstatfs64_req->buf != NULL) {
    resp_size += aconv_struct_statfs64_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  fstatfs64_adjust_write_pointers(fstatfs64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, fstatfs64_req, fstatfs64_req->req_size);

  /* resp_header->resp_type = fstatfs64_req->req_type; */
  resp_header->resp_rsc_const = fstatfs64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fstatfs64(void  *request) {
  int ret;
  struct fstatfs64_req *req = (struct fstatfs64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, sizeof(struct statfs64), req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_fstatfs64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct fstatfs64_req *fstatfs64_req = (struct fstatfs64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_statfs64(fstatfs64_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_statfs64_size(my_arch, client_arch);
    free(fstatfs64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fsync_exec(void *req, enum arch client_arch) {
  struct fsync_req *fsync_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fsync_req = (struct fsync_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fsync_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fsync_req),
      rsc2str(fsync_req->req_rsc_const), fsync_req->req_rsc_const,
      fsync_req->req_type, fsync_req->req_type, 
      fsync_req->req_size, fsync_req->req_size);

  if(fsync_req->req_size < sizeof(struct fsync_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX)", fsync_req->fd, fsync_req->fd);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, fsync_req, fsync_req->req_size);

  /* resp_header->resp_type = fsync_req->req_type; */
  resp_header->resp_rsc_const = fsync_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_fsync(void  *request) {
  int ret;
  struct fsync_req *req = (struct fsync_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd);
  
  return ret;
}

struct sys_resp_header *rscs_post_fsync_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_ftruncate64_exec(void *req, enum arch client_arch) {
  struct ftruncate64_req *ftruncate64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  ftruncate64_req = (struct ftruncate64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(ftruncate64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(ftruncate64_req),
      rsc2str(ftruncate64_req->req_rsc_const), ftruncate64_req->req_rsc_const,
      ftruncate64_req->req_type, ftruncate64_req->req_type, 
      ftruncate64_req->req_size, ftruncate64_req->req_size);

  if(ftruncate64_req->req_size < sizeof(struct ftruncate64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); length = %ld (0x%lX)", ftruncate64_req->fd, ftruncate64_req->fd, ftruncate64_req->length, ftruncate64_req->length);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, ftruncate64_req, ftruncate64_req->req_size);

  /* resp_header->resp_type = ftruncate64_req->req_type; */
  resp_header->resp_rsc_const = ftruncate64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_ftruncate64(void  *request) {
  int ret;
  struct ftruncate64_req *req = (struct ftruncate64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->length);
  
  return ret;
}

struct sys_resp_header *rscs_post_ftruncate64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_getdents64_exec(void *req, enum arch client_arch) {
  struct getdents64_req *getdents64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  getdents64_req = (struct getdents64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(getdents64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(getdents64_req),
      rsc2str(getdents64_req->req_rsc_const), getdents64_req->req_rsc_const,
      getdents64_req->req_type, getdents64_req->req_type, 
      getdents64_req->req_size, getdents64_req->req_size);

  if(getdents64_req->req_size < sizeof(struct getdents64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %u (0x%lX); dirp = %p (0x%lX); count = %u (0x%lX)", getdents64_req->fd, getdents64_req->fd, getdents64_req->dirp, getdents64_req->dirp, getdents64_req->count, getdents64_req->count);

  
  resp_size = sizeof(struct sys_resp_header);
  if(getdents64_req->dirp != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'count' argument. */
    /* The client can have changed the value of unsigned int count if it was less than
     * the size of dirp into server arch. So If unsigned int count is equal
     * to this value I need to change it to the right value on client arch. */
    if(getdents64_req->count == aconv_struct_dirent64_size(client_arch, my_arch)) {
      resp_size += aconv_struct_dirent64_size(my_arch, client_arch);
    } else {
      resp_size += getdents64_req->count; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  getdents64_adjust_write_pointers(getdents64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, getdents64_req, getdents64_req->req_size);

  /* resp_header->resp_type = getdents64_req->req_type; */
  resp_header->resp_rsc_const = getdents64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_getdents64(void  *request) {
  int ret;
  struct getdents64_req *req = (struct getdents64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->dirp, req->count);
  
  return ret;
}

struct sys_resp_header *rscs_post_getdents64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct getdents64_req *getdents64_req = (struct getdents64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_dirent64(getdents64_req->dirp, my_arch, client_arch, mem);
    mem += aconv_struct_dirent64_size(my_arch, client_arch);
    free(getdents64_req->dirp);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_getpeername_exec(void *req, enum arch client_arch) {
  struct getpeername_req *getpeername_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  getpeername_req = (struct getpeername_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(getpeername_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(getpeername_req),
      rsc2str(getpeername_req->req_rsc_const), getpeername_req->req_rsc_const,
      getpeername_req->req_type, getpeername_req->req_type, 
      getpeername_req->req_size, getpeername_req->req_size);

  if(getpeername_req->req_size < sizeof(struct getpeername_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); name = %p (0x%lX); namelen = %p (0x%lX)", getpeername_req->s, getpeername_req->s, getpeername_req->name, getpeername_req->name, getpeername_req->namelen, getpeername_req->namelen);

   
  /* Adjusts the read pointers of the request */
  getpeername_adjust_read_pointers(getpeername_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(getpeername_req->namelen != NULL) {
    resp_size += aconv_socklen_t_size(my_arch, client_arch); 
  }
  if(getpeername_req->name != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'namelen' argument. */
    /* The client can have changed the value of socklen_t *namelen if it was less than
     * the size of name into server arch. So If socklen_t *namelen is equal
     * to this value I need to change it to the right value on client arch. */
    if(*(getpeername_req->namelen) == aconv_struct_sockaddr_size(client_arch, my_arch)) {
      resp_size += aconv_struct_sockaddr_size(my_arch, client_arch);
    } else {
      resp_size += *(getpeername_req->namelen); 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  getpeername_adjust_write_pointers(getpeername_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, getpeername_req, getpeername_req->req_size);

  /* resp_header->resp_type = getpeername_req->req_type; */
  resp_header->resp_rsc_const = getpeername_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_getpeername(void  *request) {
  int ret;
  struct getpeername_req *req = (struct getpeername_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->name, req->namelen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->name),
			(unsigned long)(req->namelen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_getpeername_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct getpeername_req *getpeername_req = (struct getpeername_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_socklen_t(getpeername_req->namelen, my_arch, client_arch, mem);
    mem += aconv_socklen_t_size(my_arch, client_arch);
    aconv_struct_sockaddr(getpeername_req->name, my_arch, client_arch, mem);
    mem += aconv_struct_sockaddr_size(my_arch, client_arch);
    free(getpeername_req->name);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_getsockname_exec(void *req, enum arch client_arch) {
  struct getsockname_req *getsockname_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  getsockname_req = (struct getsockname_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(getsockname_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(getsockname_req),
      rsc2str(getsockname_req->req_rsc_const), getsockname_req->req_rsc_const,
      getsockname_req->req_type, getsockname_req->req_type, 
      getsockname_req->req_size, getsockname_req->req_size);

  if(getsockname_req->req_size < sizeof(struct getsockname_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); name = %p (0x%lX); namelen = %p (0x%lX)", getsockname_req->s, getsockname_req->s, getsockname_req->name, getsockname_req->name, getsockname_req->namelen, getsockname_req->namelen);

   
  /* Adjusts the read pointers of the request */
  getsockname_adjust_read_pointers(getsockname_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(getsockname_req->namelen != NULL) {
    resp_size += aconv_socklen_t_size(my_arch, client_arch); 
  }
  if(getsockname_req->name != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'namelen' argument. */
    /* The client can have changed the value of socklen_t *namelen if it was less than
     * the size of name into server arch. So If socklen_t *namelen is equal
     * to this value I need to change it to the right value on client arch. */
    if(*(getsockname_req->namelen) == aconv_struct_sockaddr_size(client_arch, my_arch)) {
      resp_size += aconv_struct_sockaddr_size(my_arch, client_arch);
    } else {
      resp_size += *(getsockname_req->namelen); 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  getsockname_adjust_write_pointers(getsockname_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, getsockname_req, getsockname_req->req_size);

  /* resp_header->resp_type = getsockname_req->req_type; */
  resp_header->resp_rsc_const = getsockname_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_getsockname(void  *request) {
  int ret;
  struct getsockname_req *req = (struct getsockname_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->name, req->namelen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->name),
			(unsigned long)(req->namelen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_getsockname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct getsockname_req *getsockname_req = (struct getsockname_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_socklen_t(getsockname_req->namelen, my_arch, client_arch, mem);
    mem += aconv_socklen_t_size(my_arch, client_arch);
    aconv_struct_sockaddr(getsockname_req->name, my_arch, client_arch, mem);
    mem += aconv_struct_sockaddr_size(my_arch, client_arch);
    free(getsockname_req->name);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_getsockopt_exec(void *req, enum arch client_arch) {
  struct getsockopt_req *getsockopt_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  getsockopt_req = (struct getsockopt_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(getsockopt_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(getsockopt_req),
      rsc2str(getsockopt_req->req_rsc_const), getsockopt_req->req_rsc_const,
      getsockopt_req->req_type, getsockopt_req->req_type, 
      getsockopt_req->req_size, getsockopt_req->req_size);

  if(getsockopt_req->req_size < sizeof(struct getsockopt_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); level = %ld (0x%lX); optname = %ld (0x%lX); optval = %p (0x%lX); optlen = %p (0x%lX)", getsockopt_req->s, getsockopt_req->s, getsockopt_req->level, getsockopt_req->level, getsockopt_req->optname, getsockopt_req->optname, getsockopt_req->optval, getsockopt_req->optval, getsockopt_req->optlen, getsockopt_req->optlen);

   
  /* Adjusts the read pointers of the request */
  getsockopt_adjust_read_pointers(getsockopt_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(getsockopt_req->optlen != NULL) {
    resp_size += aconv_socklen_t_size(my_arch, client_arch); 
  }
  if(getsockopt_req->optval != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'optlen' argument. */
    /* The client can have changed the value of socklen_t *optlen if it was less than
     * the size of optval into server arch. So If socklen_t *optlen is equal
     * to this value I need to change it to the right value on client arch. */
    if(*(getsockopt_req->optlen) == aconv_bytes_size(*(getsockopt_req->optlen), client_arch, my_arch)) {
      resp_size += aconv_bytes_size(*(getsockopt_req->optlen), my_arch, client_arch);
    } else {
      resp_size += *(getsockopt_req->optlen); 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  getsockopt_adjust_write_pointers(getsockopt_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, getsockopt_req, getsockopt_req->req_size);

  /* resp_header->resp_type = getsockopt_req->req_type; */
  resp_header->resp_rsc_const = getsockopt_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_getsockopt(void  *request) {
  int ret;
  struct getsockopt_req *req = (struct getsockopt_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->level, req->optname, req->optval, req->optlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->level),
			(unsigned long)(req->optname),
			(unsigned long)(req->optval),
			(unsigned long)(req->optlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_getsockopt_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct getsockopt_req *getsockopt_req = (struct getsockopt_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_socklen_t(getsockopt_req->optlen, my_arch, client_arch, mem);
    mem += aconv_socklen_t_size(my_arch, client_arch);
    aconv_bytes(getsockopt_req->optval, my_arch, client_arch, mem, *(getsockopt_req->optlen));
    mem += aconv_bytes_size(*(getsockopt_req->optlen), my_arch, client_arch);
    free(getsockopt_req->optval);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_gettimeofday_exec(void *req, enum arch client_arch) {
  struct gettimeofday_req *gettimeofday_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  gettimeofday_req = (struct gettimeofday_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(gettimeofday_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(gettimeofday_req),
      rsc2str(gettimeofday_req->req_rsc_const), gettimeofday_req->req_rsc_const,
      gettimeofday_req->req_type, gettimeofday_req->req_type, 
      gettimeofday_req->req_size, gettimeofday_req->req_size);

  if(gettimeofday_req->req_size < sizeof(struct gettimeofday_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: tv = %p (0x%lX); tz = %p (0x%lX)", gettimeofday_req->tv, gettimeofday_req->tv, gettimeofday_req->tz, gettimeofday_req->tz);

  
  resp_size = sizeof(struct sys_resp_header);
  if(gettimeofday_req->tv != NULL) {
    resp_size += aconv_struct_timeval_size(my_arch, client_arch); 
  }
  if(gettimeofday_req->tz != NULL) {
    resp_size += aconv_struct_timezone_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  gettimeofday_adjust_write_pointers(gettimeofday_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, gettimeofday_req, gettimeofday_req->req_size);

  /* resp_header->resp_type = gettimeofday_req->req_type; */
  resp_header->resp_rsc_const = gettimeofday_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_gettimeofday(void  *request) {
  int ret;
  struct gettimeofday_req *req = (struct gettimeofday_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->tv, req->tz);
  
  return ret;
}

struct sys_resp_header *rscs_post_gettimeofday_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct gettimeofday_req *gettimeofday_req = (struct gettimeofday_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_timeval(gettimeofday_req->tv, my_arch, client_arch, mem);
    mem += aconv_struct_timeval_size(my_arch, client_arch);
    free(gettimeofday_req->tv);
    aconv_struct_timezone(gettimeofday_req->tz, my_arch, client_arch, mem);
    mem += aconv_struct_timezone_size(my_arch, client_arch);
    free(gettimeofday_req->tz);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_getxattr_exec(void *req, enum arch client_arch) {
  struct getxattr_req *getxattr_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  getxattr_req = (struct getxattr_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(getxattr_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(getxattr_req),
      rsc2str(getxattr_req->req_rsc_const), getxattr_req->req_rsc_const,
      getxattr_req->req_type, getxattr_req->req_type, 
      getxattr_req->req_size, getxattr_req->req_size);

  if(getxattr_req->req_size < sizeof(struct getxattr_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", getxattr_req->path, getxattr_req->path, getxattr_req->name, getxattr_req->name, getxattr_req->value, getxattr_req->value, getxattr_req->size, getxattr_req->size);

   
  /* Adjusts the read pointers of the request */
  getxattr_adjust_read_pointers(getxattr_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(getxattr_req->value != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'size' argument. */
    /* The client can have changed the value of size_t size if it was less than
     * the size of value into server arch. So If size_t size is equal
     * to this value I need to change it to the right value on client arch. */
    if(getxattr_req->size == aconv_bytes_size(getxattr_req->size, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(getxattr_req->size, my_arch, client_arch);
    } else {
      resp_size += getxattr_req->size; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  getxattr_adjust_write_pointers(getxattr_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, getxattr_req, getxattr_req->req_size);

  /* resp_header->resp_type = getxattr_req->req_type; */
  resp_header->resp_rsc_const = getxattr_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_getxattr(void  *request) {
  int ret;
  struct getxattr_req *req = (struct getxattr_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->name, req->value, req->size);
  
  return ret;
}

struct sys_resp_header *rscs_post_getxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct getxattr_req *getxattr_req = (struct getxattr_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(getxattr_req->value, my_arch, client_arch, mem, getxattr_req->size);
    mem += aconv_bytes_size(getxattr_req->size, my_arch, client_arch);
    free(getxattr_req->value);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_lchown_exec(void *req, enum arch client_arch) {
  struct lchown_req *lchown_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  lchown_req = (struct lchown_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(lchown_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(lchown_req),
      rsc2str(lchown_req->req_rsc_const), lchown_req->req_rsc_const,
      lchown_req->req_type, lchown_req->req_type, 
      lchown_req->req_size, lchown_req->req_size);

  if(lchown_req->req_size < sizeof(struct lchown_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", lchown_req->path, lchown_req->path, lchown_req->owner, lchown_req->owner, lchown_req->group, lchown_req->group);

   
  /* Adjusts the read pointers of the request */
  lchown_adjust_read_pointers(lchown_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, lchown_req, lchown_req->req_size);

  /* resp_header->resp_type = lchown_req->req_type; */
  resp_header->resp_rsc_const = lchown_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_lchown(void  *request) {
  int ret;
  struct lchown_req *req = (struct lchown_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_lchown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_lchown32_exec(void *req, enum arch client_arch) {
  struct lchown32_req *lchown32_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  lchown32_req = (struct lchown32_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(lchown32_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(lchown32_req),
      rsc2str(lchown32_req->req_rsc_const), lchown32_req->req_rsc_const,
      lchown32_req->req_type, lchown32_req->req_type, 
      lchown32_req->req_size, lchown32_req->req_size);

  if(lchown32_req->req_size < sizeof(struct lchown32_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); owner = %ld (0x%lX); group = %ld (0x%lX)", lchown32_req->path, lchown32_req->path, lchown32_req->owner, lchown32_req->owner, lchown32_req->group, lchown32_req->group);

   
  /* Adjusts the read pointers of the request */
  lchown32_adjust_read_pointers(lchown32_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, lchown32_req, lchown32_req->req_size);

  /* resp_header->resp_type = lchown32_req->req_type; */
  resp_header->resp_rsc_const = lchown32_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_lchown32(void  *request) {
  int ret;
  struct lchown32_req *req = (struct lchown32_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->owner, req->group);
  
  return ret;
}

struct sys_resp_header *rscs_post_lchown32_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_lgetxattr_exec(void *req, enum arch client_arch) {
  struct lgetxattr_req *lgetxattr_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  lgetxattr_req = (struct lgetxattr_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(lgetxattr_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(lgetxattr_req),
      rsc2str(lgetxattr_req->req_rsc_const), lgetxattr_req->req_rsc_const,
      lgetxattr_req->req_type, lgetxattr_req->req_type, 
      lgetxattr_req->req_size, lgetxattr_req->req_size);

  if(lgetxattr_req->req_size < sizeof(struct lgetxattr_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); name = %p (0x%lX); value = %p (0x%lX); size = %ld (0x%lX)", lgetxattr_req->path, lgetxattr_req->path, lgetxattr_req->name, lgetxattr_req->name, lgetxattr_req->value, lgetxattr_req->value, lgetxattr_req->size, lgetxattr_req->size);

   
  /* Adjusts the read pointers of the request */
  lgetxattr_adjust_read_pointers(lgetxattr_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(lgetxattr_req->value != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'size' argument. */
    /* The client can have changed the value of size_t size if it was less than
     * the size of value into server arch. So If size_t size is equal
     * to this value I need to change it to the right value on client arch. */
    if(lgetxattr_req->size == aconv_bytes_size(lgetxattr_req->size, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(lgetxattr_req->size, my_arch, client_arch);
    } else {
      resp_size += lgetxattr_req->size; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  lgetxattr_adjust_write_pointers(lgetxattr_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, lgetxattr_req, lgetxattr_req->req_size);

  /* resp_header->resp_type = lgetxattr_req->req_type; */
  resp_header->resp_rsc_const = lgetxattr_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_lgetxattr(void  *request) {
  int ret;
  struct lgetxattr_req *req = (struct lgetxattr_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->name, req->value, req->size);
  
  return ret;
}

struct sys_resp_header *rscs_post_lgetxattr_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct lgetxattr_req *lgetxattr_req = (struct lgetxattr_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(lgetxattr_req->value, my_arch, client_arch, mem, lgetxattr_req->size);
    mem += aconv_bytes_size(lgetxattr_req->size, my_arch, client_arch);
    free(lgetxattr_req->value);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_link_exec(void *req, enum arch client_arch) {
  struct link_req *link_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  link_req = (struct link_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(link_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(link_req),
      rsc2str(link_req->req_rsc_const), link_req->req_rsc_const,
      link_req->req_type, link_req->req_type, 
      link_req->req_size, link_req->req_size);

  if(link_req->req_size < sizeof(struct link_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", link_req->oldpath, link_req->oldpath, link_req->newpath, link_req->newpath);

   
  /* Adjusts the read pointers of the request */
  link_adjust_read_pointers(link_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, link_req, link_req->req_size);

  /* resp_header->resp_type = link_req->req_type; */
  resp_header->resp_rsc_const = link_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_link(void  *request) {
  int ret;
  struct link_req *req = (struct link_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->oldpath, req->newpath);
  
  return ret;
}

struct sys_resp_header *rscs_post_link_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_listen_exec(void *req, enum arch client_arch) {
  struct listen_req *listen_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  listen_req = (struct listen_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(listen_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(listen_req),
      rsc2str(listen_req->req_rsc_const), listen_req->req_rsc_const,
      listen_req->req_type, listen_req->req_type, 
      listen_req->req_size, listen_req->req_size);

  if(listen_req->req_size < sizeof(struct listen_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: sockfd = %ld (0x%lX); backlog = %ld (0x%lX)", listen_req->sockfd, listen_req->sockfd, listen_req->backlog, listen_req->backlog);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, listen_req, listen_req->req_size);

  /* resp_header->resp_type = listen_req->req_type; */
  resp_header->resp_rsc_const = listen_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_listen(void  *request) {
  int ret;
  struct listen_req *req = (struct listen_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->sockfd, req->backlog);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->sockfd),
			(unsigned long)(req->backlog) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_listen_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_lseek_exec(void *req, enum arch client_arch) {
  struct lseek_req *lseek_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  lseek_req = (struct lseek_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(lseek_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(lseek_req),
      rsc2str(lseek_req->req_rsc_const), lseek_req->req_rsc_const,
      lseek_req->req_type, lseek_req->req_type, 
      lseek_req->req_size, lseek_req->req_size);

  if(lseek_req->req_size < sizeof(struct lseek_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fildes = %ld (0x%lX); offset = %ld (0x%lX); whence = %ld (0x%lX)", lseek_req->fildes, lseek_req->fildes, lseek_req->offset, lseek_req->offset, lseek_req->whence, lseek_req->whence);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, lseek_req, lseek_req->req_size);

  /* resp_header->resp_type = lseek_req->req_type; */
  resp_header->resp_rsc_const = lseek_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_lseek(void  *request) {
  int ret;
  struct lseek_req *req = (struct lseek_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fildes, req->offset, req->whence);
  
  return ret;
}

struct sys_resp_header *rscs_post_lseek_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_lstat64_exec(void *req, enum arch client_arch) {
  struct lstat64_req *lstat64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  lstat64_req = (struct lstat64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(lstat64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(lstat64_req),
      rsc2str(lstat64_req->req_rsc_const), lstat64_req->req_rsc_const,
      lstat64_req->req_type, lstat64_req->req_type, 
      lstat64_req->req_size, lstat64_req->req_size);

  if(lstat64_req->req_size < sizeof(struct lstat64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", lstat64_req->path, lstat64_req->path, lstat64_req->buf, lstat64_req->buf);

   
  /* Adjusts the read pointers of the request */
  lstat64_adjust_read_pointers(lstat64_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(lstat64_req->buf != NULL) {
    resp_size += aconv_struct_stat64_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  lstat64_adjust_write_pointers(lstat64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, lstat64_req, lstat64_req->req_size);

  /* resp_header->resp_type = lstat64_req->req_type; */
  resp_header->resp_rsc_const = lstat64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_lstat64(void  *request) {
  int ret;
  struct lstat64_req *req = (struct lstat64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_lstat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct lstat64_req *lstat64_req = (struct lstat64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_stat64(lstat64_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_stat64_size(my_arch, client_arch);
    free(lstat64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_mkdir_exec(void *req, enum arch client_arch) {
  struct mkdir_req *mkdir_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  mkdir_req = (struct mkdir_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(mkdir_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(mkdir_req),
      rsc2str(mkdir_req->req_rsc_const), mkdir_req->req_rsc_const,
      mkdir_req->req_type, mkdir_req->req_type, 
      mkdir_req->req_size, mkdir_req->req_size);

  if(mkdir_req->req_size < sizeof(struct mkdir_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: pathname = %p (0x%lX); mode = %ld (0x%lX)", mkdir_req->pathname, mkdir_req->pathname, mkdir_req->mode, mkdir_req->mode);

   
  /* Adjusts the read pointers of the request */
  mkdir_adjust_read_pointers(mkdir_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, mkdir_req, mkdir_req->req_size);

  /* resp_header->resp_type = mkdir_req->req_type; */
  resp_header->resp_rsc_const = mkdir_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_mkdir(void  *request) {
  int ret;
  struct mkdir_req *req = (struct mkdir_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->pathname, req->mode);
  
  return ret;
}

struct sys_resp_header *rscs_post_mkdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_mount_exec(void *req, enum arch client_arch) {
  struct mount_req *mount_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  mount_req = (struct mount_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(mount_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(mount_req),
      rsc2str(mount_req->req_rsc_const), mount_req->req_rsc_const,
      mount_req->req_type, mount_req->req_type, 
      mount_req->req_size, mount_req->req_size);

  if(mount_req->req_size < sizeof(struct mount_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: source = %p (0x%lX); target = %p (0x%lX); filesystemtype = %p (0x%lX); mountflags = %lu (0x%lX); data = %p (0x%lX)", mount_req->source, mount_req->source, mount_req->target, mount_req->target, mount_req->filesystemtype, mount_req->filesystemtype, mount_req->mountflags, mount_req->mountflags, mount_req->data, mount_req->data);

   
  /* Adjusts the read pointers of the request */
  mount_adjust_read_pointers(mount_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, mount_req, mount_req->req_size);

  /* resp_header->resp_type = mount_req->req_type; */
  resp_header->resp_rsc_const = mount_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_mount(void  *request) {
  int ret;
  struct mount_req *req = (struct mount_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->source, req->target, req->filesystemtype, req->mountflags, req->data);
  
  return ret;
}

struct sys_resp_header *rscs_post_mount_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_open_exec(void *req, enum arch client_arch) {
  struct open_req *open_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  open_req = (struct open_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(open_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(open_req),
      rsc2str(open_req->req_rsc_const), open_req->req_rsc_const,
      open_req->req_type, open_req->req_type, 
      open_req->req_size, open_req->req_size);

  if(open_req->req_size < sizeof(struct open_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: pathname = %p (0x%lX); flags = %ld (0x%lX)", open_req->pathname, open_req->pathname, open_req->flags, open_req->flags);

   
  /* Adjusts the read pointers of the request */
  open_adjust_read_pointers(open_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, open_req, open_req->req_size);

  /* resp_header->resp_type = open_req->req_type; */
  resp_header->resp_rsc_const = open_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_open(void  *request) {
  int ret;
  struct open_req *req = (struct open_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->pathname, req->flags);
  
  return ret;
}

struct sys_resp_header *rscs_post_open_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_pread64_exec(void *req, enum arch client_arch) {
  struct pread64_req *pread64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  pread64_req = (struct pread64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(pread64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(pread64_req),
      rsc2str(pread64_req->req_rsc_const), pread64_req->req_rsc_const,
      pread64_req->req_type, pread64_req->req_type, 
      pread64_req->req_size, pread64_req->req_size);

  if(pread64_req->req_size < sizeof(struct pread64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX); offset = %ld (0x%lX)", pread64_req->fd, pread64_req->fd, pread64_req->buf, pread64_req->buf, pread64_req->count, pread64_req->count, pread64_req->offset, pread64_req->offset);

  
  resp_size = sizeof(struct sys_resp_header);
  if(pread64_req->buf != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'count' argument. */
    /* The client can have changed the value of size_t count if it was less than
     * the size of buf into server arch. So If size_t count is equal
     * to this value I need to change it to the right value on client arch. */
    if(pread64_req->count == aconv_bytes_size(pread64_req->count, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(pread64_req->count, my_arch, client_arch);
    } else {
      resp_size += pread64_req->count; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  pread64_adjust_write_pointers(pread64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, pread64_req, pread64_req->req_size);

  /* resp_header->resp_type = pread64_req->req_type; */
  resp_header->resp_rsc_const = pread64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_pread64(void  *request) {
  int ret;
  struct pread64_req *req = (struct pread64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->buf, req->count, req->offset);
  
  return ret;
}

struct sys_resp_header *rscs_post_pread64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct pread64_req *pread64_req = (struct pread64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(pread64_req->buf, my_arch, client_arch, mem, pread64_req->count);
    mem += aconv_bytes_size(pread64_req->count, my_arch, client_arch);
    free(pread64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_pwrite64_exec(void *req, enum arch client_arch) {
  struct pwrite64_req *pwrite64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  pwrite64_req = (struct pwrite64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(pwrite64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(pwrite64_req),
      rsc2str(pwrite64_req->req_rsc_const), pwrite64_req->req_rsc_const,
      pwrite64_req->req_type, pwrite64_req->req_type, 
      pwrite64_req->req_size, pwrite64_req->req_size);

  if(pwrite64_req->req_size < sizeof(struct pwrite64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX); offset = %ld (0x%lX)", pwrite64_req->fd, pwrite64_req->fd, pwrite64_req->buf, pwrite64_req->buf, pwrite64_req->count, pwrite64_req->count, pwrite64_req->offset, pwrite64_req->offset);

   
  /* Adjusts the read pointers of the request */
  pwrite64_adjust_read_pointers(pwrite64_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, pwrite64_req, pwrite64_req->req_size);

  /* resp_header->resp_type = pwrite64_req->req_type; */
  resp_header->resp_rsc_const = pwrite64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_pwrite64(void  *request) {
  int ret;
  struct pwrite64_req *req = (struct pwrite64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->buf, req->count, req->offset);
  
  return ret;
}

struct sys_resp_header *rscs_post_pwrite64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_read_exec(void *req, enum arch client_arch) {
  struct read_req *read_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  read_req = (struct read_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(read_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(read_req),
      rsc2str(read_req->req_rsc_const), read_req->req_rsc_const,
      read_req->req_type, read_req->req_type, 
      read_req->req_size, read_req->req_size);

  if(read_req->req_size < sizeof(struct read_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX)", read_req->fd, read_req->fd, read_req->buf, read_req->buf, read_req->count, read_req->count);

  
  resp_size = sizeof(struct sys_resp_header);
  if(read_req->buf != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'count' argument. */
    /* The client can have changed the value of size_t count if it was less than
     * the size of buf into server arch. So If size_t count is equal
     * to this value I need to change it to the right value on client arch. */
    if(read_req->count == aconv_bytes_size(read_req->count, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(read_req->count, my_arch, client_arch);
    } else {
      resp_size += read_req->count; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  read_adjust_write_pointers(read_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, read_req, read_req->req_size);

  /* resp_header->resp_type = read_req->req_type; */
  resp_header->resp_rsc_const = read_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_read(void  *request) {
  int ret;
  struct read_req *req = (struct read_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->buf, req->count);
  
  return ret;
}

struct sys_resp_header *rscs_post_read_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct read_req *read_req = (struct read_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(read_req->buf, my_arch, client_arch, mem, read_req->count);
    mem += aconv_bytes_size(read_req->count, my_arch, client_arch);
    free(read_req->buf);
  }
    
  /* If the right size of the buffer is returned by the system call, 
   * I use it to send back only the part of the buffer with data */
  /* resp->resp_size = sizeof(struct sys_resp_header); */
  /* Note: I suppose that the buffer is the last data into the response, 
   * So I can subtract the unused buffer space, otherwise this doesn't 
   * work. */
  if( resp->resp_retval >= 0 ) {
    if(((struct read_req *)req)->buf != NULL)
      resp->resp_size -= (((struct read_req *)req)->count - resp->resp_retval);
  }
 
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_readlink_exec(void *req, enum arch client_arch) {
  struct readlink_req *readlink_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  readlink_req = (struct readlink_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(readlink_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(readlink_req),
      rsc2str(readlink_req->req_rsc_const), readlink_req->req_rsc_const,
      readlink_req->req_type, readlink_req->req_type, 
      readlink_req->req_size, readlink_req->req_size);

  if(readlink_req->req_size < sizeof(struct readlink_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX); bufsiz = %ld (0x%lX)", readlink_req->path, readlink_req->path, readlink_req->buf, readlink_req->buf, readlink_req->bufsiz, readlink_req->bufsiz);

   
  /* Adjusts the read pointers of the request */
  readlink_adjust_read_pointers(readlink_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(readlink_req->buf != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'bufsiz' argument. */
    /* The client can have changed the value of size_t bufsiz if it was less than
     * the size of buf into server arch. So If size_t bufsiz is equal
     * to this value I need to change it to the right value on client arch. */
    if(readlink_req->bufsiz == readlink_req->bufsiz) {
      resp_size += readlink_req->bufsiz;
    } else {
      resp_size += readlink_req->bufsiz; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  readlink_adjust_write_pointers(readlink_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, readlink_req, readlink_req->req_size);

  /* resp_header->resp_type = readlink_req->req_type; */
  resp_header->resp_rsc_const = readlink_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_readlink(void  *request) {
  int ret;
  struct readlink_req *req = (struct readlink_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->buf, req->bufsiz);
  
  return ret;
}

struct sys_resp_header *rscs_post_readlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct readlink_req *readlink_req = (struct readlink_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_string(readlink_req->buf, my_arch, client_arch, mem);
    mem += readlink_req->bufsiz;
    free(readlink_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_recv_exec(void *req, enum arch client_arch) {
  struct recv_req *recv_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  recv_req = (struct recv_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(recv_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(recv_req),
      rsc2str(recv_req->req_rsc_const), recv_req->req_rsc_const,
      recv_req->req_type, recv_req->req_type, 
      recv_req->req_size, recv_req->req_size);

  if(recv_req->req_size < sizeof(struct recv_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX)", recv_req->s, recv_req->s, recv_req->buf, recv_req->buf, recv_req->len, recv_req->len, recv_req->flags, recv_req->flags);

  
  resp_size = sizeof(struct sys_resp_header);
  if(recv_req->buf != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'len' argument. */
    /* The client can have changed the value of size_t len if it was less than
     * the size of buf into server arch. So If size_t len is equal
     * to this value I need to change it to the right value on client arch. */
    if(recv_req->len == aconv_bytes_size(recv_req->len, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(recv_req->len, my_arch, client_arch);
    } else {
      resp_size += recv_req->len; 
    }
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  recv_adjust_write_pointers(recv_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, recv_req, recv_req->req_size);

  /* resp_header->resp_type = recv_req->req_type; */
  resp_header->resp_rsc_const = recv_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_recv(void  *request) {
  int ret;
  struct recv_req *req = (struct recv_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->buf, req->len, req->flags);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->buf),
			(unsigned long)(req->len),
			(unsigned long)(req->flags) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_recv_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct recv_req *recv_req = (struct recv_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(recv_req->buf, my_arch, client_arch, mem, recv_req->len);
    mem += aconv_bytes_size(recv_req->len, my_arch, client_arch);
    free(recv_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_recvfrom_exec(void *req, enum arch client_arch) {
  struct recvfrom_req *recvfrom_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  recvfrom_req = (struct recvfrom_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(recvfrom_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(recvfrom_req),
      rsc2str(recvfrom_req->req_rsc_const), recvfrom_req->req_rsc_const,
      recvfrom_req->req_type, recvfrom_req->req_type, 
      recvfrom_req->req_size, recvfrom_req->req_size);

  if(recvfrom_req->req_size < sizeof(struct recvfrom_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX); from = %p (0x%lX); fromlen = %p (0x%lX)", recvfrom_req->s, recvfrom_req->s, recvfrom_req->buf, recvfrom_req->buf, recvfrom_req->len, recvfrom_req->len, recvfrom_req->flags, recvfrom_req->flags, recvfrom_req->from, recvfrom_req->from, recvfrom_req->fromlen, recvfrom_req->fromlen);

   
  /* Adjusts the read pointers of the request */
  recvfrom_adjust_read_pointers(recvfrom_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(recvfrom_req->buf != NULL) {
    /* Here a don't use a aconv_*_size() function, because the size 
     * of the pointed memory is given by 'len' argument. */
    /* The client can have changed the value of size_t len if it was less than
     * the size of buf into server arch. So If size_t len is equal
     * to this value I need to change it to the right value on client arch. */
    if(recvfrom_req->len == aconv_bytes_size(recvfrom_req->len, client_arch, my_arch)) {
      resp_size += aconv_bytes_size(recvfrom_req->len, my_arch, client_arch);
    } else {
      resp_size += recvfrom_req->len; 
    }
  }
  if(recvfrom_req->fromlen != NULL) {
    resp_size += aconv_socklen_t_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  recvfrom_adjust_write_pointers(recvfrom_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, recvfrom_req, recvfrom_req->req_size);

  /* resp_header->resp_type = recvfrom_req->req_type; */
  resp_header->resp_rsc_const = recvfrom_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_recvfrom(void  *request) {
  int ret;
  struct recvfrom_req *req = (struct recvfrom_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->buf, req->len, req->flags, req->from, req->fromlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->buf),
			(unsigned long)(req->len),
			(unsigned long)(req->flags),
			(unsigned long)(req->from),
			(unsigned long)(req->fromlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_recvfrom_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct recvfrom_req *recvfrom_req = (struct recvfrom_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_bytes(recvfrom_req->buf, my_arch, client_arch, mem, recvfrom_req->len);
    mem += aconv_bytes_size(recvfrom_req->len, my_arch, client_arch);
    free(recvfrom_req->buf);
    aconv_socklen_t(recvfrom_req->fromlen, my_arch, client_arch, mem);
    mem += aconv_socklen_t_size(my_arch, client_arch);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_rename_exec(void *req, enum arch client_arch) {
  struct rename_req *rename_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  rename_req = (struct rename_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(rename_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(rename_req),
      rsc2str(rename_req->req_rsc_const), rename_req->req_rsc_const,
      rename_req->req_type, rename_req->req_type, 
      rename_req->req_size, rename_req->req_size);

  if(rename_req->req_size < sizeof(struct rename_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", rename_req->oldpath, rename_req->oldpath, rename_req->newpath, rename_req->newpath);

   
  /* Adjusts the read pointers of the request */
  rename_adjust_read_pointers(rename_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, rename_req, rename_req->req_size);

  /* resp_header->resp_type = rename_req->req_type; */
  resp_header->resp_rsc_const = rename_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_rename(void  *request) {
  int ret;
  struct rename_req *req = (struct rename_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->oldpath, req->newpath);
  
  return ret;
}

struct sys_resp_header *rscs_post_rename_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_rmdir_exec(void *req, enum arch client_arch) {
  struct rmdir_req *rmdir_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  rmdir_req = (struct rmdir_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(rmdir_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(rmdir_req),
      rsc2str(rmdir_req->req_rsc_const), rmdir_req->req_rsc_const,
      rmdir_req->req_type, rmdir_req->req_type, 
      rmdir_req->req_size, rmdir_req->req_size);

  if(rmdir_req->req_size < sizeof(struct rmdir_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: pathname = %p (0x%lX)", rmdir_req->pathname, rmdir_req->pathname);

   
  /* Adjusts the read pointers of the request */
  rmdir_adjust_read_pointers(rmdir_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, rmdir_req, rmdir_req->req_size);

  /* resp_header->resp_type = rmdir_req->req_type; */
  resp_header->resp_rsc_const = rmdir_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_rmdir(void  *request) {
  int ret;
  struct rmdir_req *req = (struct rmdir_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->pathname);
  
  return ret;
}

struct sys_resp_header *rscs_post_rmdir_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_send_exec(void *req, enum arch client_arch) {
  struct send_req *send_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  send_req = (struct send_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(send_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(send_req),
      rsc2str(send_req->req_rsc_const), send_req->req_rsc_const,
      send_req->req_type, send_req->req_type, 
      send_req->req_size, send_req->req_size);

  if(send_req->req_size < sizeof(struct send_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX)", send_req->s, send_req->s, send_req->buf, send_req->buf, send_req->len, send_req->len, send_req->flags, send_req->flags);

   
  /* Adjusts the read pointers of the request */
  send_adjust_read_pointers(send_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, send_req, send_req->req_size);

  /* resp_header->resp_type = send_req->req_type; */
  resp_header->resp_rsc_const = send_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_send(void  *request) {
  int ret;
  struct send_req *req = (struct send_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->buf, req->len, req->flags);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->buf),
			(unsigned long)(req->len),
			(unsigned long)(req->flags) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_send_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_sendto_exec(void *req, enum arch client_arch) {
  struct sendto_req *sendto_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  sendto_req = (struct sendto_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(sendto_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(sendto_req),
      rsc2str(sendto_req->req_rsc_const), sendto_req->req_rsc_const,
      sendto_req->req_type, sendto_req->req_type, 
      sendto_req->req_size, sendto_req->req_size);

  if(sendto_req->req_size < sizeof(struct sendto_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); buf = %p (0x%lX); len = %ld (0x%lX); flags = %ld (0x%lX); to = %p (0x%lX); tolen = %ld (0x%lX)", sendto_req->s, sendto_req->s, sendto_req->buf, sendto_req->buf, sendto_req->len, sendto_req->len, sendto_req->flags, sendto_req->flags, sendto_req->to, sendto_req->to, sendto_req->tolen, sendto_req->tolen);

   
  /* Adjusts the read pointers of the request */
  sendto_adjust_read_pointers(sendto_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, sendto_req, sendto_req->req_size);

  /* resp_header->resp_type = sendto_req->req_type; */
  resp_header->resp_rsc_const = sendto_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_sendto(void  *request) {
  int ret;
  struct sendto_req *req = (struct sendto_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->buf, req->len, req->flags, req->to, req->tolen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->buf),
			(unsigned long)(req->len),
			(unsigned long)(req->flags),
			(unsigned long)(req->to),
			(unsigned long)(req->tolen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_sendto_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_setdomainname_exec(void *req, enum arch client_arch) {
  struct setdomainname_req *setdomainname_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  setdomainname_req = (struct setdomainname_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(setdomainname_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(setdomainname_req),
      rsc2str(setdomainname_req->req_rsc_const), setdomainname_req->req_rsc_const,
      setdomainname_req->req_type, setdomainname_req->req_type, 
      setdomainname_req->req_size, setdomainname_req->req_size);

  if(setdomainname_req->req_size < sizeof(struct setdomainname_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: name = %p (0x%lX); len = %ld (0x%lX)", setdomainname_req->name, setdomainname_req->name, setdomainname_req->len, setdomainname_req->len);

   
  /* Adjusts the read pointers of the request */
  setdomainname_adjust_read_pointers(setdomainname_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, setdomainname_req, setdomainname_req->req_size);

  /* resp_header->resp_type = setdomainname_req->req_type; */
  resp_header->resp_rsc_const = setdomainname_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_setdomainname(void  *request) {
  int ret;
  struct setdomainname_req *req = (struct setdomainname_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->name, req->len);
  
  return ret;
}

struct sys_resp_header *rscs_post_setdomainname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_sethostname_exec(void *req, enum arch client_arch) {
  struct sethostname_req *sethostname_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  sethostname_req = (struct sethostname_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(sethostname_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(sethostname_req),
      rsc2str(sethostname_req->req_rsc_const), sethostname_req->req_rsc_const,
      sethostname_req->req_type, sethostname_req->req_type, 
      sethostname_req->req_size, sethostname_req->req_size);

  if(sethostname_req->req_size < sizeof(struct sethostname_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: name = %p (0x%lX); len = %ld (0x%lX)", sethostname_req->name, sethostname_req->name, sethostname_req->len, sethostname_req->len);

   
  /* Adjusts the read pointers of the request */
  sethostname_adjust_read_pointers(sethostname_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, sethostname_req, sethostname_req->req_size);

  /* resp_header->resp_type = sethostname_req->req_type; */
  resp_header->resp_rsc_const = sethostname_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_sethostname(void  *request) {
  int ret;
  struct sethostname_req *req = (struct sethostname_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->name, req->len);
  
  return ret;
}

struct sys_resp_header *rscs_post_sethostname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_setsockopt_exec(void *req, enum arch client_arch) {
  struct setsockopt_req *setsockopt_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  setsockopt_req = (struct setsockopt_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(setsockopt_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(setsockopt_req),
      rsc2str(setsockopt_req->req_rsc_const), setsockopt_req->req_rsc_const,
      setsockopt_req->req_type, setsockopt_req->req_type, 
      setsockopt_req->req_size, setsockopt_req->req_size);

  if(setsockopt_req->req_size < sizeof(struct setsockopt_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); level = %ld (0x%lX); optname = %ld (0x%lX); optval = %p (0x%lX); optlen = %ld (0x%lX)", setsockopt_req->s, setsockopt_req->s, setsockopt_req->level, setsockopt_req->level, setsockopt_req->optname, setsockopt_req->optname, setsockopt_req->optval, setsockopt_req->optval, setsockopt_req->optlen, setsockopt_req->optlen);

   
  /* Adjusts the read pointers of the request */
  setsockopt_adjust_read_pointers(setsockopt_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, setsockopt_req, setsockopt_req->req_size);

  /* resp_header->resp_type = setsockopt_req->req_type; */
  resp_header->resp_rsc_const = setsockopt_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_setsockopt(void  *request) {
  int ret;
  struct setsockopt_req *req = (struct setsockopt_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->level, req->optname, req->optval, req->optlen);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->level),
			(unsigned long)(req->optname),
			(unsigned long)(req->optval),
			(unsigned long)(req->optlen) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_setsockopt_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_settimeofday_exec(void *req, enum arch client_arch) {
  struct settimeofday_req *settimeofday_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  settimeofday_req = (struct settimeofday_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(settimeofday_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(settimeofday_req),
      rsc2str(settimeofday_req->req_rsc_const), settimeofday_req->req_rsc_const,
      settimeofday_req->req_type, settimeofday_req->req_type, 
      settimeofday_req->req_size, settimeofday_req->req_size);

  if(settimeofday_req->req_size < sizeof(struct settimeofday_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: tv = %p (0x%lX); tz = %p (0x%lX)", settimeofday_req->tv, settimeofday_req->tv, settimeofday_req->tz, settimeofday_req->tz);

   
  /* Adjusts the read pointers of the request */
  settimeofday_adjust_read_pointers(settimeofday_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, settimeofday_req, settimeofday_req->req_size);

  /* resp_header->resp_type = settimeofday_req->req_type; */
  resp_header->resp_rsc_const = settimeofday_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_settimeofday(void  *request) {
  int ret;
  struct settimeofday_req *req = (struct settimeofday_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->tv, req->tz);
  
  return ret;
}

struct sys_resp_header *rscs_post_settimeofday_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_shutdown_exec(void *req, enum arch client_arch) {
  struct shutdown_req *shutdown_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  shutdown_req = (struct shutdown_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(shutdown_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(shutdown_req),
      rsc2str(shutdown_req->req_rsc_const), shutdown_req->req_rsc_const,
      shutdown_req->req_type, shutdown_req->req_type, 
      shutdown_req->req_size, shutdown_req->req_size);

  if(shutdown_req->req_size < sizeof(struct shutdown_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: s = %ld (0x%lX); how = %ld (0x%lX)", shutdown_req->s, shutdown_req->s, shutdown_req->how, shutdown_req->how);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, shutdown_req, shutdown_req->req_size);

  /* resp_header->resp_type = shutdown_req->req_type; */
  resp_header->resp_rsc_const = shutdown_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_shutdown(void  *request) {
  int ret;
  struct shutdown_req *req = (struct shutdown_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->s, req->how);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->s),
			(unsigned long)(req->how) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_shutdown_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_socket_exec(void *req, enum arch client_arch) {
  struct socket_req *socket_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  socket_req = (struct socket_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(socket_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(socket_req),
      rsc2str(socket_req->req_rsc_const), socket_req->req_rsc_const,
      socket_req->req_type, socket_req->req_type, 
      socket_req->req_size, socket_req->req_size);

  if(socket_req->req_size < sizeof(struct socket_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: domain = %ld (0x%lX); type = %ld (0x%lX); protocol = %ld (0x%lX)", socket_req->domain, socket_req->domain, socket_req->type, socket_req->type, socket_req->protocol, socket_req->protocol);

  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, socket_req, socket_req->req_size);

  /* resp_header->resp_type = socket_req->req_type; */
  resp_header->resp_rsc_const = socket_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_socket(void  *request) {
  int ret;
  struct socket_req *req = (struct socket_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
#ifdef __x86_64__
  ret = syscall(nr_and_sys->nr, req->domain, req->type, req->protocol);
#else
       
    {
	    unsigned long args[] = { (unsigned long)(req->domain),
			(unsigned long)(req->type),
			(unsigned long)(req->protocol) };
	    ret = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
    }
#endif
  
  return ret;
}

struct sys_resp_header *rscs_post_socket_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_stat64_exec(void *req, enum arch client_arch) {
  struct stat64_req *stat64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  stat64_req = (struct stat64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(stat64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(stat64_req),
      rsc2str(stat64_req->req_rsc_const), stat64_req->req_rsc_const,
      stat64_req->req_type, stat64_req->req_type, 
      stat64_req->req_size, stat64_req->req_size);

  if(stat64_req->req_size < sizeof(struct stat64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", stat64_req->path, stat64_req->path, stat64_req->buf, stat64_req->buf);

   
  /* Adjusts the read pointers of the request */
  stat64_adjust_read_pointers(stat64_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(stat64_req->buf != NULL) {
    resp_size += aconv_struct_stat64_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  stat64_adjust_write_pointers(stat64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, stat64_req, stat64_req->req_size);

  /* resp_header->resp_type = stat64_req->req_type; */
  resp_header->resp_rsc_const = stat64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_stat64(void  *request) {
  int ret;
  struct stat64_req *req = (struct stat64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_stat64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct stat64_req *stat64_req = (struct stat64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_stat64(stat64_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_stat64_size(my_arch, client_arch);
    free(stat64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_statfs64_exec(void *req, enum arch client_arch) {
  struct statfs64_req *statfs64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  statfs64_req = (struct statfs64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(statfs64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(statfs64_req),
      rsc2str(statfs64_req->req_rsc_const), statfs64_req->req_rsc_const,
      statfs64_req->req_type, statfs64_req->req_type, 
      statfs64_req->req_size, statfs64_req->req_size);

  if(statfs64_req->req_size < sizeof(struct statfs64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); buf = %p (0x%lX)", statfs64_req->path, statfs64_req->path, statfs64_req->buf, statfs64_req->buf);

   
  /* Adjusts the read pointers of the request */
  statfs64_adjust_read_pointers(statfs64_req);
  
  resp_size = sizeof(struct sys_resp_header);
  if(statfs64_req->buf != NULL) {
    resp_size += aconv_struct_statfs64_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  statfs64_adjust_write_pointers(statfs64_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, statfs64_req, statfs64_req->req_size);

  /* resp_header->resp_type = statfs64_req->req_type; */
  resp_header->resp_rsc_const = statfs64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_statfs64(void  *request) {
  int ret;
  struct statfs64_req *req = (struct statfs64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, sizeof(struct statfs64), req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_statfs64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct statfs64_req *statfs64_req = (struct statfs64_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_statfs64(statfs64_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_statfs64_size(my_arch, client_arch);
    free(statfs64_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_symlink_exec(void *req, enum arch client_arch) {
  struct symlink_req *symlink_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  symlink_req = (struct symlink_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(symlink_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(symlink_req),
      rsc2str(symlink_req->req_rsc_const), symlink_req->req_rsc_const,
      symlink_req->req_type, symlink_req->req_type, 
      symlink_req->req_size, symlink_req->req_size);

  if(symlink_req->req_size < sizeof(struct symlink_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: oldpath = %p (0x%lX); newpath = %p (0x%lX)", symlink_req->oldpath, symlink_req->oldpath, symlink_req->newpath, symlink_req->newpath);

   
  /* Adjusts the read pointers of the request */
  symlink_adjust_read_pointers(symlink_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, symlink_req, symlink_req->req_size);

  /* resp_header->resp_type = symlink_req->req_type; */
  resp_header->resp_rsc_const = symlink_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_symlink(void  *request) {
  int ret;
  struct symlink_req *req = (struct symlink_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->oldpath, req->newpath);
  
  return ret;
}

struct sys_resp_header *rscs_post_symlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_truncate64_exec(void *req, enum arch client_arch) {
  struct truncate64_req *truncate64_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  truncate64_req = (struct truncate64_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(truncate64_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(truncate64_req),
      rsc2str(truncate64_req->req_rsc_const), truncate64_req->req_rsc_const,
      truncate64_req->req_type, truncate64_req->req_type, 
      truncate64_req->req_size, truncate64_req->req_size);

  if(truncate64_req->req_size < sizeof(struct truncate64_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: path = %p (0x%lX); length = %ld (0x%lX)", truncate64_req->path, truncate64_req->path, truncate64_req->length, truncate64_req->length);

   
  /* Adjusts the read pointers of the request */
  truncate64_adjust_read_pointers(truncate64_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, truncate64_req, truncate64_req->req_size);

  /* resp_header->resp_type = truncate64_req->req_type; */
  resp_header->resp_rsc_const = truncate64_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_truncate64(void  *request) {
  int ret;
  struct truncate64_req *req = (struct truncate64_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->path, req->length);
  
  return ret;
}

struct sys_resp_header *rscs_post_truncate64_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_umount2_exec(void *req, enum arch client_arch) {
  struct umount2_req *umount2_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  umount2_req = (struct umount2_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(umount2_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(umount2_req),
      rsc2str(umount2_req->req_rsc_const), umount2_req->req_rsc_const,
      umount2_req->req_type, umount2_req->req_type, 
      umount2_req->req_size, umount2_req->req_size);

  if(umount2_req->req_size < sizeof(struct umount2_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: target = %p (0x%lX); flags = %ld (0x%lX)", umount2_req->target, umount2_req->target, umount2_req->flags, umount2_req->flags);

   
  /* Adjusts the read pointers of the request */
  umount2_adjust_read_pointers(umount2_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, umount2_req, umount2_req->req_size);

  /* resp_header->resp_type = umount2_req->req_type; */
  resp_header->resp_rsc_const = umount2_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_umount2(void  *request) {
  int ret;
  struct umount2_req *req = (struct umount2_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->target, req->flags);
  
  return ret;
}

struct sys_resp_header *rscs_post_umount2_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_uname_exec(void *req, enum arch client_arch) {
  struct uname_req *uname_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  uname_req = (struct uname_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(uname_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(uname_req),
      rsc2str(uname_req->req_rsc_const), uname_req->req_rsc_const,
      uname_req->req_type, uname_req->req_type, 
      uname_req->req_size, uname_req->req_size);

  if(uname_req->req_size < sizeof(struct uname_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: buf = %p (0x%lX)", uname_req->buf, uname_req->buf);

  
  resp_size = sizeof(struct sys_resp_header);
  if(uname_req->buf != NULL) {
    resp_size += aconv_struct_utsname_size(my_arch, client_arch); 
  }
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  uname_adjust_write_pointers(uname_req, resp_header, resp_size, client_arch);
   
  RSC_EXDUMP(RSCD_REQ_RESP, uname_req, uname_req->req_size);

  /* resp_header->resp_type = uname_req->req_type; */
  resp_header->resp_rsc_const = uname_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_uname(void  *request) {
  int ret;
  struct uname_req *req = (struct uname_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_uname_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  /* Now I manage the write buffer. If server and client arch. are the same
   * I've nothing to do, otherwise I need to convert all the write buffers 
   * and free the memory malloced for write-only buffers */
  if(my_arch != client_arch) {
    struct uname_req *uname_req = (struct uname_req *)req;
    void *mem = ((void *)resp) + sizeof(struct sys_resp_header);
    aconv_struct_utsname(uname_req->buf, my_arch, client_arch, mem);
    mem += aconv_struct_utsname_size(my_arch, client_arch);
    free(uname_req->buf);
  }
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_unlink_exec(void *req, enum arch client_arch) {
  struct unlink_req *unlink_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  unlink_req = (struct unlink_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(unlink_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(unlink_req),
      rsc2str(unlink_req->req_rsc_const), unlink_req->req_rsc_const,
      unlink_req->req_type, unlink_req->req_type, 
      unlink_req->req_size, unlink_req->req_size);

  if(unlink_req->req_size < sizeof(struct unlink_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: pathname = %p (0x%lX)", unlink_req->pathname, unlink_req->pathname);

   
  /* Adjusts the read pointers of the request */
  unlink_adjust_read_pointers(unlink_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, unlink_req, unlink_req->req_size);

  /* resp_header->resp_type = unlink_req->req_type; */
  resp_header->resp_rsc_const = unlink_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_unlink(void  *request) {
  int ret;
  struct unlink_req *req = (struct unlink_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->pathname);
  
  return ret;
}

struct sys_resp_header *rscs_post_unlink_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_utime_exec(void *req, enum arch client_arch) {
  struct utime_req *utime_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  utime_req = (struct utime_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(utime_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(utime_req),
      rsc2str(utime_req->req_rsc_const), utime_req->req_rsc_const,
      utime_req->req_type, utime_req->req_type, 
      utime_req->req_size, utime_req->req_size);

  if(utime_req->req_size < sizeof(struct utime_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: filename = %p (0x%lX); buf = %p (0x%lX)", utime_req->filename, utime_req->filename, utime_req->buf, utime_req->buf);

   
  /* Adjusts the read pointers of the request */
  utime_adjust_read_pointers(utime_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, utime_req, utime_req->req_size);

  /* resp_header->resp_type = utime_req->req_type; */
  resp_header->resp_rsc_const = utime_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_utime(void  *request) {
  int ret;
  struct utime_req *req = (struct utime_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->filename, req->buf);
  
  return ret;
}

struct sys_resp_header *rscs_post_utime_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_utimes_exec(void *req, enum arch client_arch) {
  struct utimes_req *utimes_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  utimes_req = (struct utimes_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(utimes_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(utimes_req),
      rsc2str(utimes_req->req_rsc_const), utimes_req->req_rsc_const,
      utimes_req->req_type, utimes_req->req_type, 
      utimes_req->req_size, utimes_req->req_size);

  if(utimes_req->req_size < sizeof(struct utimes_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: filename = %p (0x%lX); tv = %p (0x%lX)", utimes_req->filename, utimes_req->filename, utimes_req->tv, utimes_req->tv);

   
  /* Adjusts the read pointers of the request */
  utimes_adjust_read_pointers(utimes_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, utimes_req, utimes_req->req_size);

  /* resp_header->resp_type = utimes_req->req_type; */
  resp_header->resp_rsc_const = utimes_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_utimes(void  *request) {
  int ret;
  struct utimes_req *req = (struct utimes_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->filename, req->tv);
  
  return ret;
}

struct sys_resp_header *rscs_post_utimes_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_write_exec(void *req, enum arch client_arch) {
  struct write_req *write_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  write_req = (struct write_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(write_req->req_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(write_req),
      rsc2str(write_req->req_rsc_const), write_req->req_rsc_const,
      write_req->req_type, write_req->req_type, 
      write_req->req_size, write_req->req_size);

  if(write_req->req_size < sizeof(struct write_req))
    return NULL;

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); buf = %p (0x%lX); count = %ld (0x%lX)", write_req->fd, write_req->fd, write_req->buf, write_req->buf, write_req->count, write_req->count);

   
  /* Adjusts the read pointers of the request */
  write_adjust_read_pointers(write_req);
  
  resp_size = sizeof(struct sys_resp_header);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  RSC_EXDUMP(RSCD_REQ_RESP, write_req, write_req->req_size);

  /* resp_header->resp_type = write_req->req_type; */
  resp_header->resp_rsc_const = write_req->req_rsc_const;
  return resp_header;
}

int rscs_exec_write(void  *request) {
  int ret;
  struct write_req *req = (struct write_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
     
  ret = syscall(nr_and_sys->nr, req->fd, req->buf, req->count);
  
  return ret;
}

struct sys_resp_header *rscs_post_write_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    resp->resp_errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
   
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}


struct sys_resp_header *rscs_pre_ioctl_exec(void *req, enum arch client_arch) {
  struct ioctl_req *ioctl_req;
  struct sys_resp_header *resp_header;
  int resp_size, index;
  struct ioctl_entry *ioctle;

  ioctl_req = (struct ioctl_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(ioctl_req->req_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(ioctl_req),
      rsc2str(ioctl_req->req_rsc_const), ioctl_req->req_rsc_const,
      ioctl_req->req_type, ioctl_req->req_type, 
      ioctl_req->req_size, ioctl_req->req_size);

  if(ioctl_req->req_size < sizeof(struct ioctl_req))
    return NULL;

  index = ioctl_search(ioctl_req->request);
  ioctle = ioctl_getel(index);
  assert(ioctle != NULL);

    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: d = %ld (0x%lX); request = %ld (0x%lX); arg = %p (0x%lX)", 
      ioctl_req->d, ioctl_req->d, ioctl_req->request, ioctl_req->request, ioctl_req->arg, ioctl_req->arg);

  /* Adjusts the read pointers of the request */
  ioctl_adjust_read_pointers(ioctl_req, ioctle->size_type);
  
  resp_size = sizeof(struct sys_resp_header);
  if(ioctl_req->arg != NULL && (ioctle->size_type & IOCTL_W))
    resp_size += ioctle->size_type & IOCTL_LENMASK;
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

   
  /* Adjusts the write pointers of the request */
  ioctl_adjust_write_pointers(ioctl_req, resp_header, resp_size, ioctle->size_type, client_arch);
  
  /* resp_header->resp_type = ioctl_req->req_type; */
  resp_header->resp_rsc_const = ioctl_req->req_rsc_const;

  return resp_header;

}  
int rscs_exec_ioctl(void  *request) {
  int ret;
  struct ioctl_req *req = (struct ioctl_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);
  ret = syscall(nr_and_sys->nr, req->d, req->request, req->arg);

  return ret;
}
    
struct sys_resp_header *rscs_post_ioctl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}

struct sys_resp_header *rscs_pre_fcntl_exec(void *req, enum arch client_arch) {
  struct fcntl_req *fcntl_req;
  struct sys_resp_header *resp_header;
  int resp_size;

  fcntl_req = (struct fcntl_req *) req;

  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s:", rsc2str(fcntl_req->req_type));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): rsc_const = %s (0x%X); req_type = %d (0x%lX); req_size = %d (0x%lX) bytes", 
      sizeof(fcntl_req),
      rsc2str(fcntl_req->req_rsc_const), fcntl_req->req_rsc_const,
      fcntl_req->req_type, fcntl_req->req_type, 
      fcntl_req->req_size, fcntl_req->req_size);

  if(fcntl_req->req_size < sizeof(struct fcntl_req))
    return NULL;
    
  RSC_DEBUG(RSCD_REQ_RESP, "\tArguments: fd = %ld (0x%lX); cmd = %ld (0x%lX);", fcntl_req->fd, fcntl_req->fd, fcntl_req->cmd, fcntl_req->cmd);

  resp_size = sizeof(struct sys_resp_header);
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK_W)
    resp_size += sizeof(struct flock);
  resp_header = calloc(1, resp_size); 
  if(resp_header == NULL)
    return NULL;
  resp_header->resp_type = RSC_SYS_RESP;
  resp_header->resp_size = resp_size;

  /* If there is a third argument and it is a 'struct flock' pointer */
  if(fcntl_req->cmd_type & FCNTL_3RD_FLOCK) {
    /* Adjusts the read pointers of the request */
    fcntl_adjust_read_pointers(fcntl_req);
   
    /* Adjusts the write pointers of the request */
    fcntl_adjust_write_pointers(fcntl_req, resp_header, resp_size, client_arch);
  }
  
  resp_header->resp_rsc_const = fcntl_req->req_rsc_const;

  return resp_header;
}
int rscs_exec_fcntl(void  *request) {
  int ret;
  struct fcntl_req *req = (struct fcntl_req *)request;
  struct nr_and_sys *nr_and_sys;
  nr_and_sys = rsc2nr(req->req_rsc_const, my_arch);

  if(req->cmd_type & FCNTL_NO_3RD_ARG) {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd);
  } else if(req->cmd_type & FCNTL_3RD_LONG) {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd, req->third.arg);
  } else {
    ret = syscall(nr_and_sys->nr, req->fd, req->cmd, req->third.lock);
  }

  return ret;  
} 

struct sys_resp_header *rscs_post_fcntl_exec(void *req, struct sys_resp_header *resp, int retval, int errnoval, enum arch client_arch) {
  resp->resp_retval = retval;
  resp->resp_errno =  errnoval;
  /* workaround for the wrap_in_getsock() pc->erno problem */
  if(resp->resp_retval != -1)
    errno = 0;
  /* workaround for the wrap_in_getsock() pc->erno problem: END*/
  
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s:", rsc2str(resp->resp_rsc_const));
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader(%dB): resp_type = %d (0x%lX); size = %d (0x%lX) bytes; resp_retval = %d (0x%lX); errno = %d (0x%lX)", 
      sizeof(struct sys_resp_header),
      resp->resp_type, resp->resp_type,
      resp->resp_size, resp->resp_size, 
      resp->resp_retval, resp->resp_retval, 
      resp->resp_errno, resp->resp_errno);

  return resp;
}
/*########################################################################*/
/*##                                                                    ##*/
/*##  REQUEST MANAGEMENT                                                ##*/
/*##                                                                    ##*/
/*########################################################################*/

#if 0
void *req_func_recvmsg(void *req) {
	struct recvmsg_req *recvmsg_req;
  struct recvmsg_resp *recvmsg_resp;
  struct nr_and_sys *nr_and_sys;
  void *data, *new_ptr;
  int read_buffer_size, i;
  
  recvmsg_req = (struct recvmsg_req *) req;
  RSC_DEBUG(RSCD_REQ_RESP, "==> REQUEST %s (%p):", rsc2str(recvmsg_req->req_type), recvmsg_req);
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: req_type = %d (0x%X); req_size = %d (0x%X) bytes", recvmsg_req->req_type, recvmsg_req->req_type, recvmsg_req->req_size, recvmsg_req->req_size);
  
	RSC_DEBUG(RSCD_REQ_RESP, "\ts = %ld; msg = * ; flags = %ld", recvmsg_req->s, recvmsg_req->flags);
  
  recvmsg_adjust_read_pointers(recvmsg_req);
  RSC_PRINT_MSGHDR(RSCD_REQ_RESP, &(recvmsg_req->msg));
	
	recvmsg_resp = malloc(sizeof(struct recvmsg_resp));
	if(recvmsg_resp == NULL)
	  return NULL;
  bzero(recvmsg_resp, sizeof(struct recvmsg_resp));
	
	recvmsg_resp->resp_type = recvmsg_req->req_type;

  if( (nr_and_sys = rsc2nr(recvmsg_req->req_type, my_arch)) == NULL)
    return NULL;
	{
		unsigned long args[] = {(unsigned long)(recvmsg_req->s), (unsigned long)(&(recvmsg_req->msg)), (unsigned long)(recvmsg_req->flags)};
		recvmsg_resp->resp_retval = syscall(nr_and_sys->nr, nr_and_sys->sys, args);
	}
	recvmsg_resp->resp_errno = errno;
  /* I need to add the buffers read  */
  read_buffer_size = 0;
  if(recvmsg_resp->resp_retval > 0) {
    for(i = 0; i < recvmsg_req->msg.msg_iovlen; i++)
      read_buffer_size += recvmsg_req->msg.msg_iov[i].iov_len;
  } 
	recvmsg_resp->resp_size = sizeof(struct recvmsg_resp) + read_buffer_size;
  if(recvmsg_req->msg.msg_control != NULL)
	  recvmsg_resp->resp_size += recvmsg_req->msg.msg_controllen;
  
  if((new_ptr = realloc(recvmsg_resp, recvmsg_resp->resp_size)) == NULL)
    return NULL;
  recvmsg_resp = new_ptr;
  data = ((void *)recvmsg_resp) + sizeof(struct recvmsg_resp);
  for(i = 0; i < recvmsg_req->msg.msg_iovlen; i++) {
    memcpy(data, recvmsg_req->msg.msg_iov[i].iov_base, recvmsg_req->msg.msg_iov[i].iov_len);
    data += recvmsg_req->msg.msg_iov[i].iov_len;
  }

  if(recvmsg_req->msg.msg_control != NULL)
    memcpy(data, recvmsg_req->msg.msg_control, recvmsg_req->msg.msg_controllen);
  
  recvmsg_resp->msg_controllen = recvmsg_req->msg.msg_controllen;
    
  RSC_DEBUG(RSCD_REQ_RESP, "<== RESPONSE %s (%p):", rsc2str(recvmsg_resp->resp_rsc_const), recvmsg_resp);
  RSC_DEBUG(RSCD_REQ_RESP, "\tHeader: resp_type = %d (0x%X); resp_size = %d (0x%X) bytes; resp_retval = %d (0x%X); resp_errno = %d (0x%X)", recvmsg_resp->resp_type, recvmsg_resp->resp_type, recvmsg_resp->resp_size, recvmsg_resp->resp_size, recvmsg_resp->resp_retval, recvmsg_resp->resp_retval, recvmsg_resp->resp_errno, recvmsg_resp->resp_errno);
  return recvmsg_resp;
}
#endif

/*########################################################################*/
/*##                                                                    ##*/
/*##  PUBLIC FUNCTIONS                                                  ##*/
/*##                                                                    ##*/
/*########################################################################*/

int rscs_init(enum arch server_arch) {
  my_arch = server_arch;
  ioctl_list = init_list(100);
  if(ioctl_list == NULL)
    return -1;

  return 0;
}

void rsc_server_teardown() {
  my_arch = ACONV_ARCH_ERROR;
  teardown_list(ioctl_list, free);
  ioctl_list = NULL;
}

void *rscs_manage_request(int client_arch, void *request) {
  void *ret_data;
  struct req_header *req_hd;
 
  req_hd = (struct req_header *)request;
  req_hd->req_size = ntohl(req_hd->req_size);
  if( req_hd->req_type == RSC_IOCTL_REQ) {
	  RSC_DEBUG(RSCD_REQ_RESP,"RSC IOCTL Request management");
    ret_data = rscs_manage_ioctl_request((struct ioctl_req_header *)request);
  } else if( req_hd->req_type == RSC_SYS_REQ) {
    struct sys_req_header *req_hd;
    struct sys_resp_header *resp_hd;
    rscs_pre_exec pre_exec_f;
    int ret;
    rscs_exec exec_f;
    rscs_post_exec post_exec_f;
    req_hd = (struct sys_req_header *)request;
    /* I convert the filed of the RSC SYS request header */ 
    req_hd->req_rsc_const = ntohs(req_hd->req_rsc_const);
	  RSC_DEBUG(RSCD_REQ_RESP,"RSC SYS Request management: %X(%s)", req_hd->req_rsc_const, rsc2str(req_hd->req_rsc_const));
    if( req_hd->req_rsc_const < __RSC_FIRST || req_hd->req_rsc_const > __RSC_LAST )
      return NULL;
    pre_exec_f = rscs_pre_exec_table[req_hd->req_rsc_const];
    exec_f = rscs_exec_table[req_hd->req_rsc_const];
    post_exec_f = rscs_post_exec_table[req_hd->req_rsc_const];
    if(pre_exec_f == NULL || exec_f == NULL || post_exec_f == NULL)
      return NULL;
    if((resp_hd = pre_exec_f(request, client_arch)) == NULL)
      return NULL;
    ret = exec_f(request);
    resp_hd = post_exec_f(request, resp_hd, ret, errno, client_arch);

    /* I convert the response's header fields */ 
    resp_hd->resp_rsc_const = htons(resp_hd->resp_rsc_const);
    resp_hd->resp_size = htonl(resp_hd->resp_size);
    resp_hd->resp_retval = htonl(resp_hd->resp_retval);
    resp_hd->resp_errno = htonl(resp_hd->resp_errno);
    ret_data = resp_hd;
  } else {
    /* Bad request type */
    ret_data = NULL;
  }

  return ret_data;
}

