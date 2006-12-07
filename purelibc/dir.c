/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * dir.c: Directory management
 * 
 * Copyright 2006 Renzo Davoli University of Bologna - Italy
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License a
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */ 

#include <config.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define PURE_DIRSTREAM_SIZE 2048
#define PURE_DIRBUF_SIZE (PURE_DIRSTREAM_SIZE - 3*sizeof(int))

struct __dirstream {
	int fd;
	int bufsize;
	int bufpos;
	char buf[PURE_DIRBUF_SIZE];
	struct dirent de32;
};

DIR *opendir(const char *name)
{
	int fd;
	DIR *newdir=NULL;

	if ((fd=open(name, O_RDONLY | O_DIRECTORY)) >= 0) {
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) < 0)
			close(fd);
		else {
			newdir=(DIR *) malloc (sizeof (struct __dirstream));
			if (!newdir)
				return NULL;
			else {
				newdir->fd=fd;
				newdir->bufsize=newdir->bufpos=0;
			}
		}
	}
	return newdir;
}

int closedir(DIR *dir){
	int fd=dir->fd;
	free(dir);
	return close(fd);
}

#define _MAX_OFF_T ((__off_t) -1)

struct dirent *readdir(DIR *dir){
	register struct dirent64 *de64=readdir64(dir);
	if(de64 == NULL)
		return NULL;
	else {
		dir->de32.d_ino=de64->d_ino;
		dir->de32.d_off=(de64->d_off > _MAX_OFF_T)?_MAX_OFF_T:de64->d_off;
		dir->de32.d_reclen=de64->d_reclen;
		dir->de32.d_type=de64->d_type;
		strcpy(dir->de32.d_name,de64->d_name);
		return &(dir->de32);
	}
}

struct dirent64 *readdir64(DIR *dir){
	register struct dirent64 *this;
	this=((struct dirent64 *) (dir->buf + dir->bufpos));
	if (dir->bufsize == 0 || (dir->bufpos += this->d_reclen) >= dir->bufsize) {
		dir->bufsize = getdents64(dir->fd,(struct dirent64 *)dir->buf,PURE_DIRBUF_SIZE-1);
		if (dir->bufsize <= 0)
			return NULL;
		else
			dir->bufpos=0;
	}
	this=((struct dirent64 *) (dir->buf + dir->bufpos));
	return this;
}

int dirfd(DIR *dir){
	if (dir) 
		return dir->fd;
	else
		return -1;
}

void rewinddir(DIR *dir){
	if (dir) {
		lseek(dir->fd,0,SEEK_SET);
		dir->bufsize=dir->bufpos=0;
	}
}

void seekdir(DIR *dir, off_t offset){
	if (dir) {
		lseek(dir->fd,offset,SEEK_SET);
		dir->bufsize=dir->bufpos=0;
	}
}

off_t telldir(DIR *dir){
	if (dir) {
		off_t pos = lseek(dir->fd,0,SEEK_CUR);
		if (pos != (off_t) -1)
			return -1;
		else
			return pos + dir->bufpos;
	} else
		return -1;
}

/*
int scandir(const char *dir, struct dirent ***namelist,
		int(*filter)(const struct dirent *),
		int(*compar)(const struct dirent **, const struct dirent **)){
}*/

