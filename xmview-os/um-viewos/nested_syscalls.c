/*   This is part of um-ViewOS
 *   Application Level Environment for Networking
 *
 *   library used for compose more um-viewos modules
 *   
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
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */   

#include <stdarg.h>
#include <sys/types.h>
/*#include <sys/stat.h>*/
#include <utime.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

//verify that theese are necessary...
#include "../um-viewos/scmap.h"
#include "../um-viewos/sctab.h"

/*extern long nested_syscall(int syscallno,...);*/
#define real_fprintf	fprintf
/*extern int(*real_fprintf)(FILE *stream, const char *format, ...);*/

// management function for choosing the right behavior
unsigned char nested_inside_mod=0;
unsigned char nested_service_code=0xFF; //UM_NONE

// fake, cancel this after ..
long nested_syscall(int syscallno,...){
	va_list arglist;
	long parameters[6];
	int i,numarg;
	fprintf(stderr,"sono dentro al modulo - %d\n",syscallno);
	va_start(arglist,syscallno);
	numarg= scmap[uscno(syscallno)].nargs;
	for( i=0; i<6; i++ ){
		if( i< numarg)
			parameters[i] = va_arg(arglist,long);
		else
			parameters[i] = 0;
	}
	return syscall(syscallno,parameters[0],parameters[1],parameters[2],parameters[3],parameters[4],parameters[5]);
}

// open must consider two mode of calling: with two or three arguments
int open(const char* pathname,int flags,...){
	va_list arg_list;
	mode_t mode;
/*    printf("nest: open(%s)\n",pathname);*/
	if( flags |  O_CREAT ){
		// must consider mode too
		va_start(arg_list,flags);
		mode = va_arg(arg_list,mode_t);
		if( nested_inside_mod )
			return nested_syscall(__NR_open,(long)pathname,flags,mode);
		else 
			return syscall(__NR_open,(long)pathname,flags,mode);
	}
	else{
		if( nested_inside_mod )
			return nested_syscall(__NR_open,(long)pathname,flags);
		else 
			return syscall(__NR_open,(long)pathname,flags);
	}
}

int close(int fd){
/*    printf("nest: close()\n");*/
	if(nested_inside_mod)
		return nested_syscall(__NR_close,fd);
	else
		return syscall(__NR_close,fd);
}

int read(int fd,void* buf,size_t count){
/*    printf("nest: read(count=%d)\n",count);*/
	if(nested_inside_mod)
		return nested_syscall(__NR_read,fd,buf,count);
	else
		return syscall(__NR_read,fd,buf,count);
}

int write(int fd,const void* buf,size_t count){
/*    real_fprintf(stderr,"nest: write() - %d\n",nested_inside_mod);*/
	if( nested_inside_mod )
		return nested_syscall(__NR_write,fd,buf,count);
	else
		return syscall(__NR_write,fd,buf,count);
}

int stat(const char* pathname,struct stat* buf){
/*    real_fprintf(stderr,"Nested stat(): %d pathname %s - %ld - inside: %d\n",__NR_stat,pathname,(long)pathname,nested_inside_mod);*/
	if( nested_inside_mod)
		return nested_syscall(__NR_stat,(long)pathname,buf);
	else
		return syscall(__NR_stat,(long)pathname,buf);
}

int lstat(const char* pathname,struct stat* buf){
/*    real_fprintf(stderr,"Nested lstat(): %d pathname %s - %ld - inside: %d\n",__NR_lstat,pathname,(long)pathname,nested_inside_mod);*/
	if ( nested_inside_mod )
		return nested_syscall(__NR_lstat,(long)pathname,buf);
	else
		return syscall(__NR_lstat,(long)pathname,buf);
}

int stat64(const char* pathname,struct stat64* buf){
/*    real_fprintf(stderr,"Nested stat64(): %d pathname %s - %ld - inside: %d\n",__NR_stat64,pathname,(long)buf,nested_inside_mod);*/
	if( nested_inside_mod)
		return nested_syscall(__NR_stat64,(long)pathname,buf);
	else
		return syscall(__NR_stat64,(long)pathname,buf);
}

int lstat64(const char* pathname,struct stat64* buf){
/*    real_fprintf(stderr,"Nested lstat64(): %d pathname %s - %ld - inside: %d\n",__NR_lstat64,pathname,(long)buf,nested_inside_mod);*/
	if ( nested_inside_mod )
		return nested_syscall(__NR_lstat64,(long)pathname,buf);
	else
		return syscall(__NR_lstat64,(long)pathname,buf);
}

// TEST: stat functions are wrapper in *xstat* functions, so i have to redefine this, 
// stat won't be called by umview...
int __xstat(int ver,const char* pathname,struct stat* buf){
/*    real_fprintf(stderr,"Nested __xstat(): %d pathname %s - %ld\n - inside: %d",__NR_stat,pathname,(long)buf,nested_inside_mod);*/
	if ( nested_inside_mod )
		return nested_syscall(__NR_stat,(long)pathname,buf);
	else
		return syscall(__NR_stat,(long)pathname,buf);
}
int __lxstat64(int ver,const char* pathname,struct stat64* buf){
/*    real_fprintf(stderr,"Nested __lxstat64(): %d pathname %s - %ld - inside: %d\n",__NR_lstat64,pathname,(long)buf,nested_inside_mod);*/
	if ( nested_inside_mod )
		return nested_syscall(__NR_lstat64,(long)pathname,buf);
	else
		return syscall(__NR_lstat64,(long)pathname,buf);
}

int access(const char* pathname,int mode){
/*    printf("nest: access()\n");*/
	if( nested_inside_mod )
		return nested_syscall(__NR_access,(long)pathname,mode);
	else
		return syscall(__NR_access,(long)pathname,mode);
}

int readlink(const char* pathname,char* buf, size_t bufsize){
/*    printf("nest: readlink(pathname: %s) - %d\n",pathname,nested_inside_mod);*/
	if( nested_inside_mod )
		return nested_syscall(__NR_readlink,(long)pathname,buf,bufsize);
	else
		return syscall(__NR_readlink,(long)pathname,buf,bufsize);
}

int mkdir(const char* pathname,mode_t mode){
	if( nested_inside_mod )
		return nested_syscall(__NR_mkdir,(long)pathname,mode);
	else
		return syscall(__NR_mkdir,(long)pathname,mode);
}

int rmdir(const char* pathname){
	if( nested_inside_mod )
		return nested_syscall(__NR_rmdir,(long)pathname);
	else
		return syscall(__NR_rmdir,(long)pathname);
}

int chmod(const char* pathname,mode_t mode){
	if( nested_inside_mod )
		return nested_syscall(__NR_chmod,(long)pathname,mode);
	else
		return syscall(__NR_chmod,(long)pathname,mode);
}

int fchmod(int fd,mode_t mode){
	if( nested_inside_mod )
		return nested_syscall(__NR_fchmod,fd,mode);
	else
		return syscall(__NR_fchmod,fd,mode);
}

int chown(const char* pathname,uid_t owner,gid_t group){
	if( nested_inside_mod )
		return nested_syscall(__NR_chown,(long)pathname,owner,group);
	else
		return syscall(__NR_chown,(long)pathname,owner,group);
}

int lchown(const char* pathname,uid_t owner,gid_t group){
	if( nested_inside_mod )
		return nested_syscall(__NR_lchown,(long)pathname,owner,group);
	else
		return syscall(__NR_lchown,(long)pathname,owner,group);
}

int fchown(int fd,uid_t owner,gid_t group){
	if( nested_inside_mod )
		return nested_syscall(__NR_fchown,fd,owner,group);
	else
		return syscall(__NR_fchown,fd,owner,group);
}

int link(const char* pathname,const char* newpath){
	if( nested_inside_mod )
		return nested_syscall(__NR_link,(long)pathname,newpath);
	else
		return syscall(__NR_link,(long)pathname,newpath);
}

int unlink(const char* pathname){
/*    printf("nest: unlink(pathname: %s) - %d\n",pathname,nested_inside_mod);*/
	if( nested_inside_mod )
		return nested_syscall(__NR_unlink,(long)pathname);
	else
		return syscall(__NR_unlink,(long)pathname);
}

int symlink(const char* pathname,const char* newpath){
	if( nested_inside_mod )
		return nested_syscall(__NR_symlink,(long)pathname,(long)newpath);
	else
		return syscall(__NR_symlink,(long)pathname,(long)newpath);
}

int utime(const char* pathname,const struct utimbuf *buf){
	if(nested_inside_mod)
		return nested_syscall(__NR_utime,(long)pathname,buf);
	else
		return syscall(__NR_utime,(long)pathname,buf);
}

int utimes(const char* pathname,struct timeval tv[2]){
	if( nested_inside_mod )
		return nested_syscall(__NR_utimes,(long)pathname,tv);
	else
		return syscall(__NR_utimes,(long)pathname,tv);
}

ssize_t pread(int fs,void* buf, size_t count, off_t offset){
	if( nested_inside_mod )
		return nested_syscall(__NR_pread64,fs,buf,count,offset);
	else
		return syscall(__NR_pread64,fs,buf,count,offset);
}

ssize_t pwrite(int fs,const const void* buf, size_t count, off_t offset){
	if( nested_inside_mod )
		return nested_syscall(__NR_pwrite64,fs,buf,count,offset);
	else
		return syscall(__NR_pwrite64,fs,buf,count,offset);
}

int getdents(int fd,long dirp,unsigned int count){
	if( nested_inside_mod )
		return nested_syscall(__NR_getdents,fd,dirp,count);
	else
		return syscall(__NR_getdents,fd,dirp,count);
}

int getdents64(int fd,long dirp,unsigned int count){
	if( nested_inside_mod )
		return nested_syscall(__NR_getdents64,fd,dirp,count);
	else
		return syscall(__NR_getdents64,fd,dirp,count);
}

off_t lseek(int fd,off_t offset,int whence){
	if( nested_inside_mod )
		return nested_syscall(__NR_lseek,fd,offset,whence);
	else
		return syscall(__NR_lseek,fd,offset,whence);
}

// ---- uum_plusio calls ----

int fsync(int fd){
	if( nested_inside_mod )
		return nested_syscall(__NR_fsync,fd);
	else
		return syscall(__NR_fsync,fd);
}

int ioctl(int fd,int request,...){
	if( nested_inside_mod )
		return nested_syscall(__NR_ioctl,fd,request);
	else
		return syscall(__NR_ioctl,fd,request);
}

/*
int fcntl(int fd, int cmd){
// MANCAAAA
}
*/

int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data){
	if(nested_inside_mod)
		return nested_syscall(__NR_mount,source,target,filesystemtype,mountflags,data);
	else
		return syscall(__NR_mount,source,target,filesystemtype,mountflags,data);
}

int mount2(const char *target, int flags){
	if(nested_inside_mod)
		return nested_syscall(__NR_mount,target,flags);
	else
		return syscall(__NR_mount,target,flags);
}

int umount(const char *target){
	if(nested_inside_mod)
		return nested_syscall(__NR_umount,target);
	else
		return syscall(__NR_umount,target);
}
