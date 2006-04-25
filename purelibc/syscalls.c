/*   This is part of pure_libc (a project related to ViewOS and Virtual Square)
 *  
 *   syscalls.c: syscall mgmt
 *   
 *   Copyright 2006 Renzo Davoli University of Bologna - Italy
 *   Copyright 2005 Andrea Gasparini University of Bologna - Italy
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
 *   You should have received a copy of the GNU General Public License a
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */   

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/timex.h>
#include <sys/sendfile.h>
#include <sys/xattr.h>
#include <sys/timeb.h>
#include <utime.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <ustat.h>
#include <time.h>
#include <grp.h>
#include <limits.h>
#include <stdlib.h>
#include "pure_libc.h"

sfun _pure_syscall=syscall;

/* DAMNED! the kernel stat are different! so glibc converts the 
 *  * kernel structure. We have to make the reverse conversion! */
#ifdef __powerpc__
struct kstat {
	unsigned        kst_dev;
	ino_t           kst_ino;
	mode_t          kst_mode;
	nlink_t         kst_nlink;
	uid_t           kst_uid;
	gid_t           kst_gid;
	unsigned        kst_rdev;
	off_t           kst_size;
	unsigned long   kst_blksize;
	unsigned long   kst_blocks;
	unsigned long   kst_atime;
	unsigned long   kst_atime_nsec;
	unsigned long   kst_mtime;
	unsigned long   kst_mtime_nsec;
	unsigned long   kst_ctime;
	unsigned long   kst_ctime_nsec;
	unsigned long   k__unused4;
	unsigned long   k__unused5;
};  
#endif
#ifdef __i386__
struct kstat {
	unsigned short kst_dev;
	unsigned short k__pad1;
	unsigned long  kst_ino;
	unsigned short kst_mode;
	unsigned short kst_nlink;
	unsigned short kst_uid;
	unsigned short kst_gid;
	unsigned short kst_rdev;
	unsigned short k__pad2;
	unsigned long  kst_size;
	unsigned long  kst_blksize;
	unsigned long  kst_blocks;
	unsigned long  kst_atime;
	unsigned long  k__unused1;
	unsigned long  kst_mtime;
	unsigned long  k__unused2;
	unsigned long  kst_ctime;
	unsigned long  k__unused3;
	unsigned long  k__unused4;
	unsigned long  k__unused5;
};
#endif

#ifdef __x86_64__
struct kstat {
	unsigned long kst_dev;
	unsigned long   kst_ino;
	unsigned long    kst_nlink;

	unsigned int    kst_mode;
	unsigned int  kst_uid;
	unsigned int  kst_gid;
	unsigned int  k__pad0;

	unsigned long kst_rdev;

	long      kst_size;
	long      kst_blksize;
	long      kst_blocks;  /* Number 512-byte blocks allocated. */

	unsigned long   kst_atime;
	unsigned long   kst_atime_nsec;
	unsigned long   kst_mtime;
	unsigned long   kst_mtime_nsec;
	unsigned long   kst_ctime;
	unsigned long   kst_ctime_nsec;

	long  k__unused[3];
};
#endif

static void kstat2stat(struct kstat *kbuf,struct stat *buf)
{
	buf->st_dev= kbuf->kst_dev;
	buf->st_ino= kbuf->kst_ino;
	buf->st_mode= kbuf->kst_mode;
	buf->st_nlink= kbuf->kst_nlink;
	buf->st_uid= kbuf->kst_uid;
	buf->st_gid= kbuf->kst_gid;
	buf->st_rdev= kbuf->kst_rdev;
	buf->st_size= kbuf->kst_size;
	buf->st_blksize= kbuf->kst_blksize;
	buf->st_blocks= kbuf->kst_blocks;
	buf->st_atime= kbuf->kst_atime;
	buf->st_mtime= kbuf->kst_mtime;
	buf->st_ctime= kbuf->kst_ctime;
}

// open must consider two mode of calling: with two or three arguments
int open(const char* pathname,int flags,...){
	va_list arg_list;
	if( flags |  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return _pure_syscall(__NR_open,pathname,flags,mode);
	}
	else
		return _pure_syscall(__NR_open,pathname,flags);
}

int open64(const char* pathname,int flags,...){
	va_list arg_list;
	if( flags |  O_CREAT ){
		mode_t mode;
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		va_end(arg_list);
		return _pure_syscall(__NR_open,pathname,flags|O_LARGEFILE,mode);
	}
	else
		return _pure_syscall(__NR_open,pathname,flags|O_LARGEFILE);
}

int creat(const char *pathname, mode_t mode)
{
	return _pure_syscall(__NR_open,pathname,O_CREAT|O_WRONLY|O_TRUNC,mode);
}

int creat64(const char *pathname, mode_t mode)
{
	return _pure_syscall(__NR_open,pathname,O_CREAT|O_WRONLY|O_TRUNC|O_LARGEFILE,mode);
}

int close(int fd){
	return _pure_syscall(__NR_close,fd);
}

int read(int fd,void* buf,size_t count){
	return _pure_syscall(__NR_read,fd,buf,count);
}

int write(int fd,const void* buf,size_t count){
	return _pure_syscall(__NR_write,fd,buf,count);
}

ssize_t readv(int filedes, const struct iovec *vector,
		int count)
{
	return _pure_syscall(__NR_readv, filedes, vector, count);
}

ssize_t writev(int filedes, const struct iovec *vector,
		int count)
{
	return _pure_syscall(__NR_writev, filedes, vector, count);
}

int dup(int oldfd){
	return _pure_syscall(__NR_dup, oldfd);
}

int dup2(int oldfd, int newfd){
	return _pure_syscall(__NR_dup2, oldfd, newfd);
}

int stat(const char* pathname,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_stat,pathname,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int lstat(const char* pathname,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_lstat,pathname,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int fstat(int fildes,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_fstat,fildes,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int stat64(const char* pathname,struct stat64* buf){
	return _pure_syscall(__NR_stat64,pathname,buf);
}

int lstat64(const char* pathname,struct stat64* buf){
	return _pure_syscall(__NR_lstat64,pathname,buf);
}

int fstat64(int filedes,struct stat64* buf){
	return _pure_syscall(__NR_fstat64,filedes,buf);
}

int __xstat(int ver,const char* pathname,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_stat,pathname,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int __lxstat(int ver,const char* pathname,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_lstat,pathname,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int __fxstat(int ver,int fildes,struct stat* buf){
	struct kstat kbuf;
	int rv;
	rv=_pure_syscall(__NR_fstat,fildes,&kbuf);
	if (rv>=0)
		kstat2stat(&kbuf,buf);
	return rv;
}

int __xstat64(int ver,const char* pathname,struct stat64* buf){
	return _pure_syscall(__NR_stat64,pathname,buf);
}

int __lxstat64(int ver,const char* pathname,struct stat64* buf){
	return _pure_syscall(__NR_lstat64,pathname,buf);
}

int __fxstat64 (int ver, int fildes, struct stat64 *buf){
	return _pure_syscall(__NR_fstat64,fildes,buf);
}

int mknod(const char *pathname, mode_t mode, dev_t dev) {
	return _pure_syscall(__NR_mknod,pathname,mode,dev);
}

int __xmknod (int ver, const char *path, mode_t mode, dev_t *dev) {
	return _pure_syscall(__NR_mknod,path,mode,dev);
}

int access(const char* pathname,int mode){
	return _pure_syscall(__NR_access,pathname,mode);
}

int readlink(const char* pathname,char* buf, size_t bufsize){
	return _pure_syscall(__NR_readlink,pathname,buf,bufsize);
}

int mkdir(const char* pathname,mode_t mode){
	return _pure_syscall(__NR_mkdir,pathname,mode);
}

int rmdir(const char* pathname){
	return _pure_syscall(__NR_rmdir,pathname);
}

int chmod(const char* pathname,mode_t mode){
	return _pure_syscall(__NR_chmod,pathname,mode);
}

int fchmod(int fd,mode_t mode){
	return _pure_syscall(__NR_fchmod,fd,mode);
}

int chown(const char* pathname,uid_t owner,gid_t group){
	return _pure_syscall(__NR_chown,pathname,owner,group);
}

int lchown(const char* pathname,uid_t owner,gid_t group){
	return _pure_syscall(__NR_lchown,pathname,owner,group);
}

int fchown(int fd,uid_t owner,gid_t group){
	return _pure_syscall(__NR_fchown,fd,owner,group);
}

int link(const char* pathname,const char* newpath){
	return _pure_syscall(__NR_link,pathname,newpath);
}

int unlink(const char* pathname){
	return _pure_syscall(__NR_unlink,pathname);
}

int symlink(const char* pathname,const char* newpath){
	return _pure_syscall(__NR_symlink,pathname,newpath);
}

int rename(const char *oldpath, const char *newpath){
	return _pure_syscall(__NR_rename,oldpath,newpath);
}

int chdir(const char *path) {
	return _pure_syscall(__NR_chdir,path);
}

int fchdir(int fd) {
	return _pure_syscall(__NR_fchdir,fd);
}

int utime(const char* pathname,const struct utimbuf *buf){
	return _pure_syscall(__NR_utime,pathname,buf);
}

int utimes(const char* pathname,const struct timeval tv[2]){
	return _pure_syscall(__NR_utimes,pathname,tv);
}

ssize_t pread(int fs,void* buf, size_t count, off_t offset){
	return _pure_syscall(__NR_pread64,fs,buf,count,offset);
}

ssize_t pwrite(int fs,const void* buf, size_t count, off_t offset){
	return _pure_syscall(__NR_pwrite64,fs,buf,count,offset);
}

int getdents(int fd, long dirp,unsigned int count){
	return _pure_syscall(__NR_getdents,fd,dirp,count);
}

int getdents64(int fd, long dirp,unsigned int count){
	return _pure_syscall(__NR_getdents64,fd,dirp,count);
}

off_t lseek(int fd,off_t offset,int whence){
	return _pure_syscall(__NR_lseek,fd,offset,whence);
}

int fsync(int fd){
	return _pure_syscall(__NR_fsync,fd);
}

#if defined(__powerpc__)
/* DAMNED! Another kernel specific structure needs lib conversion! */
#include<sys/ioctl.h>
#include<termios.h>
#include"kernel_termios.ppc.h"

static void termios_k2l(struct termios *dst,struct __kernel_termios *src) {
	register int i;
	dst->c_iflag = src->c_iflag;
	dst->c_oflag = src->c_oflag;
	dst->c_cflag = src->c_cflag;
	dst->c_lflag = src->c_lflag;
	dst->c_line = src->c_line;
	dst->c_ispeed = src->c_ispeed;
	dst->c_ospeed = src->c_ospeed;
	for (i=0; i<__KERNEL_NCCS; i++)
		dst->c_cc[i]=src->c_cc[i];
	for (;i<NCCS;i++)
		dst->c_cc[i]=_POSIX_VDISABLE;
}

static void termios_l2k(struct __kernel_termios *dst,struct termios *src) {
	register int i;
	dst->c_iflag = src->c_iflag;
	dst->c_oflag = src->c_oflag;
	dst->c_cflag = src->c_cflag;
	dst->c_lflag = src->c_lflag;
	dst->c_line = src->c_line;
	dst->c_ispeed = src->c_ispeed;
	dst->c_ospeed = src->c_ospeed;
	for (i=0; i<__KERNEL_NCCS; i++)
		dst->c_cc[i]=src->c_cc[i];
}

static int ioctl_ppc(int fd,unsigned long int request, long int arg){
	int result;
	switch (request) {
		case TCGETS: {
									 struct __kernel_termios kt;
									 result = _pure_syscall (__NR_ioctl, fd, request, &kt);
									 termios_k2l((struct termios *) arg, &kt);
									 break;
								 }
		case TCSETS:
		case TCSETSW:
		case TCSETSF: {
										struct __kernel_termios kt;
										termios_l2k(&kt,(struct termios *) arg);
										result = _pure_syscall (__NR_ioctl, fd, request, &kt);
										break;
									}
		default:
									result = _pure_syscall (__NR_ioctl, fd, request, arg);
									break;
	}
	return result;
}
#endif

int ioctl(int fd,unsigned long int request, ...){
	va_list ap;
	long int arg;
	va_start(ap, request);
	arg=va_arg(ap,  long int);
	va_end(ap);
	int rv=0;
#if defined(__powerpc__)
		ioctl_ppc(fd,request,arg);
#else
		rv= _pure_syscall(__NR_ioctl,fd,request,arg);
#endif
	return rv;
}

int fcntl(int fd, int cmd, ...){
	va_list ap;
	long int arg1;
	long int arg2;
	va_start(ap, cmd);
	arg1=va_arg(ap,  long int);
	arg2=va_arg(ap,  long int);
	va_end(ap);
	return _pure_syscall(__NR_fcntl,fd,cmd,arg1,arg2);
}

int fcntl64(int fd, int cmd, ...){
	va_list ap;
	long int arg1;
	long int arg2;
	va_start(ap, cmd);
	arg1=va_arg(ap,  long int);
	arg2=va_arg(ap,  long int);
	va_end(ap);
	return _pure_syscall(__NR_fcntl64,fd,cmd,arg1,arg2);
}

int mount(const char *source, const char *target, const char *filesystemtype, unsigned  mountflags, const void *data){
	return _pure_syscall(__NR_mount,source,target,filesystemtype,mountflags,data);
}

int umount(const char *target){
	return _pure_syscall(__NR_umount,target);
}

int umount2(const char *target, int flags){
	return _pure_syscall(__NR_umount,target,flags);
}

pid_t getpid(void){
	return _pure_syscall(__NR_getpid);
}

pid_t getppid(void){
	return _pure_syscall(__NR_getppid);
}

int setpgid(pid_t pid, pid_t pgid){
	return _pure_syscall(__NR_setpgid,pid,pgid);
}

pid_t getpgid(pid_t pid){
	return _pure_syscall(__NR_getpgid,pid);
}

int setpgrp(void){
	return _pure_syscall(__NR_setpgid,0,0);
}

pid_t getpgrp(void){
	return _pure_syscall(__NR_getpgid,0);
}

int setuid(uid_t uid){
	return _pure_syscall(__NR_setuid,uid);
}

int setgid(gid_t gid){
	return _pure_syscall(__NR_setgid,gid);
}

int seteuid(uid_t euid){
	return _pure_syscall(__NR_setreuid,-1,euid);
}

int setegid(gid_t egid){
	return _pure_syscall(__NR_setregid,-1,egid);
}

uid_t getuid(void) {
	return _pure_syscall(__NR_getuid);
}

gid_t getgid(void) {
	return _pure_syscall(__NR_getgid);
}

uid_t geteuid(void) {
	return _pure_syscall(__NR_geteuid);
}

gid_t getegid(void) {
	return _pure_syscall(__NR_getegid);
}

int setreuid(uid_t ruid, uid_t euid){
	return _pure_syscall(__NR_setreuid,ruid,euid);
}

int setregid(gid_t rgid, gid_t egid){
	return _pure_syscall(__NR_setresgid,rgid,egid);
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid){
	return _pure_syscall(__NR_setresuid,ruid,euid,suid);
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid){
	return _pure_syscall(__NR_setresgid,rgid,egid,sgid);
}

int pipe(int filedes[2]) {
	return _pure_syscall(__NR_pipe,filedes);
}

mode_t umask(mode_t mask){
	return _pure_syscall(__NR_umask,mask);
}

int chroot(const char *path){
	return _pure_syscall(__NR_chroot,path);
}

int execve(const char *filename, char *const argv [], char *const envp[])
{
	return _pure_syscall(__NR_execve,filename,argv,envp);
}

void _exit(int status){
	_pure_syscall(__NR_exit,status);
	/* never reached, just to avoid "noreturn" warnings */
	_exit(status);
}

void _Exit(int status){
	_pure_syscall(__NR_exit,status);
	/* never reached, just to avoid "noreturn" warnings */
	_exit(status);
}

pid_t fork(void){
	return _pure_syscall(__NR_fork);
}

pid_t vfork(void){
	return _pure_syscall(__NR_vfork);
}

time_t time(time_t *t){
	return _pure_syscall(__NR_time,t);
}

int stime(const time_t *t){
	return _pure_syscall(__NR_stime,t);
}

/* it does not work yet */
#if 0
long int ptrace (enum __ptrace_request request, ...){
	va_list ap;
	pid_t pid;
	void *addr;
	int data;
	void *addr2;
	va_start(ap, request);
	pid=va_arg(ap, pid_t);
	addr=va_arg(ap, void *);
	data=va_arg(ap, int);
	addr2=va_arg(ap, void *);
	va_end(ap);
	return _pure_syscall(__NR_ptrace,request,pid,addr,data,addr2);
}
#endif

int nice(int inc){
	return _pure_syscall(__NR_nice,inc);
}

void sync(void){
	_pure_syscall(__NR_sync);
}

clock_t times(struct tms *buf){
	return _pure_syscall(__NR_times,buf);
}

int ustat(dev_t dev, struct ustat *ubuf){
	return _pure_syscall(__NR_ustat,dev,ubuf);
}

pid_t getsid(pid_t pid){
	return _pure_syscall(__NR_getsid,pid);
}

pid_t setsid(void){
	return _pure_syscall(__NR_setsid);
}

int sethostname(const char *name, size_t len){
	return _pure_syscall(__NR_sethostname,name,len);
}

int setrlimit(__rlimit_resource_t resource, const struct rlimit *rlim){
	return _pure_syscall(__NR_setrlimit,resource,rlim);
}

int getrlimit(__rlimit_resource_t resource, struct rlimit *rlim){ 
	return _pure_syscall(__NR_getrlimit,resource,rlim);
}

int getrusage(int who, struct rusage *usage){
	return _pure_syscall(__NR_getrusage,usage);
}

int gettimeofday(struct timeval *tv, struct timezone *tz){
	return _pure_syscall(__NR_gettimeofday, tv, tz);
}

int settimeofday(const struct timeval *tv , const struct timezone *tz){
	return _pure_syscall(__NR_settimeofday, tv, tz);
}

int getgroups(int size, gid_t list[]){
	return _pure_syscall(__NR_getgroups,size,list);
}

int setgroups(size_t size, const gid_t *list){
	return _pure_syscall(__NR_setgroups,size,list);
}

int select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout){
	return _pure_syscall(__NR__newselect,n,readfds,writefds,exceptfds,timeout);
}

int poll(struct pollfd *ufds, nfds_t nfds, int timeout){
	return _pure_syscall(__NR_poll,ufds,nfds,timeout);
}

int truncate(const char *path, off_t length){
	return _pure_syscall(__NR_truncate,path,length);
}

int ftruncate(int fd, off_t length){
	return _pure_syscall(__NR_ftruncate,fd,length);
}

int truncate64(const char *path, __off64_t length){
	return _pure_syscall(__NR_truncate64,path,length);
}

int ftruncate64(int fd, __off64_t length){
	return _pure_syscall(__NR_ftruncate64,fd,length);
}

int getpriority(__priority_which_t which, id_t who){
	return _pure_syscall(__NR_getpriority,which,who);
}

int setpriority(__priority_which_t which, id_t who, int prio){
	return _pure_syscall(__NR_getpriority,which,who,prio);
}

int statfs(const char *path, struct statfs *buf){
	return _pure_syscall(__NR_statfs,path,buf);
}

int fstatfs(int fd, struct statfs *buf){
	return _pure_syscall(__NR_fstatfs,fd,buf);
}

int statfs64(const char *path, struct statfs64 *buf){
	return _pure_syscall(__NR_statfs64,path,buf);
}

int fstatfs64(int fd, struct statfs64 *buf){
	return _pure_syscall(__NR_fstatfs64,fd,buf);
}

int getitimer(__itimer_which_t which, struct itimerval *value){
	return _pure_syscall(__NR_getitimer,which,value);
}

int setitimer(__itimer_which_t which, const struct itimerval *value, struct itimerval *ovalue){
	return _pure_syscall(__NR_setitimer,which,value,ovalue);
}

pid_t wait(int *status){
	return _pure_syscall(__NR_waitpid,-1,status,0);
}

pid_t waitpid(pid_t pid, int *status, int options){
	return _pure_syscall(__NR_waitpid,pid,status,options);
}

#ifdef __NR_waitid
int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options){
	return _pure_syscall(__NR_waitid,idtype,id,infop,options);
}
#endif

pid_t wait3(int *status, int options, struct rusage *rusage){
	return _pure_syscall(__NR_wait4,-1,status,options,rusage);
}

pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage){
	return _pure_syscall(__NR_wait4,pid,status,options,rusage);
}

int sysinfo(struct sysinfo *info){
	return _pure_syscall(__NR_sysinfo,info);
}

int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth){
	return _pure_syscall(__NR_ipc,first,second,third,ptr,fifth);
}

int setdomainname(const char *name, size_t len){
	return _pure_syscall(__NR_setdomainname,name,len);
}

int uname(struct utsname *buf){
	return _pure_syscall(__NR_uname,buf);
}

int adjtimex(struct timex *buf){
	return _pure_syscall(__NR_adjtimex,buf);
}

int sysfs(int option,...){
	switch (option) {
		case 1: {
							va_list ap;
							char *fsname;
							va_start(ap, option);
							fsname=va_arg(ap, char *);
							va_end(ap);
							return _pure_syscall(__NR_sysfs,option,fsname);
						}
		case 2: {
							va_list ap;
							unsigned int fs_index;
							char *buf;
							va_start(ap, option);
							fs_index=va_arg(ap, unsigned int);
							buf=va_arg(ap, char *);
							va_end(ap);
							return _pure_syscall(__NR_sysfs,option,fs_index,buf);
						}
		case 3:
						 return _pure_syscall(__NR_sysfs,option);
		default:
						 errno=EINVAL;
						 return -1;
	}
}

int setfsuid(uid_t fsuid){
	return _pure_syscall(__NR_setfsuid,fsuid);
}

int setfsgid(uid_t fsgid){
	return _pure_syscall(__NR_setfsgid,fsgid);
}

int _llseek(unsigned int fd, unsigned long  offset_high,  unsigned  long  offset_low,  loff_t
		       *result, unsigned int whence){
	return _pure_syscall(__NR__llseek,fd,offset_high,offset_low,result,whence);

}

int flock(int fd, int operation){
	return _pure_syscall(__NR_flock,fd,operation);
}

int fdatasync(int fd){
	return _pure_syscall(__NR_fdatasync,fd);
}

char *getcwd(char *buf, size_t size){
	int rsize;
	if (size == 0 && buf==NULL) {
		size=PATH_MAX;
		buf=malloc(size);
		if (buf==NULL) 
			return NULL;
		else {
			rsize=_pure_syscall(__NR_getcwd,buf,size);
			if (rsize>=0) {
				buf=realloc(buf,rsize);
				return buf;
			} else {
				free(buf);
				return NULL;
			}
		}
	} else {
		rsize=_pure_syscall(__NR_getcwd,buf,size);
		if (rsize>=0) 
			return buf;
		else
			return NULL;
	}
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count){
	return _pure_syscall(__NR_sendfile,out_fd,in_fd,offset,count);
}

/*
pid_t gettid(void){
	return _pure_syscall(__NR_gettid);
}*/
			
int setxattr (const char *path, const char *name,
		     const void *value, size_t size, int flags){
	return _pure_syscall(__NR_setxattr,path,name,value,size,flags);
}

int lsetxattr (const char *path, const char *name,
		      const void *value, size_t size, int flags){
	return _pure_syscall(__NR_lsetxattr,path,name,value,size,flags);
}

int fsetxattr (int fd, const char *name, const void *value,
		      size_t size, int flags){
	return _pure_syscall(__NR_fsetxattr,fd,name,value,size,flags);
}

ssize_t getxattr (const char *path, const char *name,
			 void *value, size_t size){
	return _pure_syscall(__NR_getxattr,path,name,value,size);
}

ssize_t lgetxattr (const char *path, const char *name,
			  void *value, size_t size){
	return _pure_syscall(__NR_lgetxattr,path,name,value,size);
}

ssize_t fgetxattr (int fd, const char *name, void *value,
			  size_t size) {
	return _pure_syscall(__NR_fgetxattr,fd,name,value,size);
}

ssize_t listxattr (const char *path, char *list, size_t size){
	return _pure_syscall(__NR_listxattr,path,list,size);
}

ssize_t llistxattr (const char *path, char *list, size_t size){
	return _pure_syscall(__NR_llistxattr,path,list,size);
}

ssize_t flistxattr (int fd, char *list, size_t size){
	return _pure_syscall(__NR_flistxattr,fd,list,size);
}

int removexattr (const char *path, const char *name){
	return _pure_syscall(__NR_removexattr,path,name);
}

int lremovexattr (const char *path, const char *name){
	return _pure_syscall(__NR_lremovexattr,path,name);
}

int fremovexattr (int fd, const char *name){
	return _pure_syscall(__NR_fremovexattr,fd,name);
}

int clock_getres(clockid_t clk_id, struct timespec *res){
	return _pure_syscall(__NR_clock_getres,clk_id,res);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp){
	return _pure_syscall(__NR_clock_gettime,clk_id,tp);
}

int clock_settime(clockid_t clk_id, const struct timespec *tp){
	return _pure_syscall(__NR_clock_gettime,clk_id,tp);
}

static void statfs2vfs(struct statfs *sfs,struct statvfs *vsfs)
{
	vsfs->f_bsize=sfs->f_bsize;
	vsfs->f_frsize=0;
	vsfs->f_blocks=sfs->f_blocks;
	vsfs->f_bfree=sfs->f_bfree;
	vsfs->f_bavail=sfs->f_bavail;
	vsfs->f_files=sfs->f_files;
	vsfs->f_ffree=sfs->f_ffree;
	vsfs->f_favail=sfs->f_ffree;
	/*vsfs->f_fsid=sfs->f_fsid;*/
	vsfs->f_flag=0;
	vsfs->f_namemax=sfs->f_namelen;
}

int statvfs(const char *path, struct statvfs *buf){
	struct statfs sfs;
	int rv=_pure_syscall(__NR_statfs,path,&sfs);
	statfs2vfs(&sfs,buf);
	return 0;
}

int fstatvfs(int fd, struct statvfs *buf){
	struct statfs sfs;
	int rv=_pure_syscall(__NR_fstatfs,fd,&sfs);
	statfs2vfs(&sfs,buf);
	return 0;
}

int ftime(struct timeb *tp){
	struct timeval tv;
	struct timezone tz;
	int rv=gettimeofday(&tv,&tz);
	tp->time  = tv.tv_sec;
	tp->millitm = tv.tv_usec/1000;
	tp->timezone = timezone;
	tp->dstflag = daylight;
	return rv;
}
