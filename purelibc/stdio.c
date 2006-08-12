/* This is part of pure_libc (a project related to ViewOS and Virtual Square)
 * 
 * stdio.c: stdio calls
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
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */ 

#define _IO_MTSAFE_IO
//#define DEBUG_LOCK
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <mntent.h>
#include <pthread.h>
#ifdef _IO_MTSAFE_IO
#include <bits/stdio-lock.h>

#ifdef DEBUG_LOCK
/* if (__pthread_mutex_init != ((void *)0)):
 * init functions are undefined when programs do not load libthreads
 * thus _IO_flockfile would not work (randomly blocks as it works on
 * dirty memory). When __pthread_mutex_init is not defined (i.e.
 * programs compiled without pthreads), do not call flock/funlock */

# define _IO_acquire_lock(_fp) \
	_pure_debug_printf("_IO_acquire_lock %p %p %d %d %d %d %d F%x L%d\n",_fp,_fp->_lock,_fp->_lock->mutex.__m_kind,_fp->_lock->mutex.__m_count,_fp->_lock->mutex.__m_owner,_fp->_lock->mutex.__m_lock.__status, _fp->_lock->mutex.__m_lock.__spinlock,_fp->_flags,__LINE__);\
  _IO_cleanup_region_start ((void (*) (void *)) _IO_funlockfile, (_fp));      \
  if (__pthread_mutex_init != ((void *)0)) __pthread_mutex_lock(&(_fp->_lock->mutex))

# define _IO_release_lock(_fp) \
	_pure_debug_printf("_IO_release_lock %p %p %d %d %d %d %d F%x L%d\n",_fp,_fp->_lock,_fp->_lock->mutex.__m_kind,_fp->_lock->mutex.__m_count,_fp->_lock->mutex.__m_owner,_fp->_lock->mutex.__m_lock.__status, _fp->_lock->mutex.__m_lock.__spinlock,_fp->_flags,__LINE__);\
  if (__pthread_mutex_init != ((void *)0)) __pthread_mutex_unlock (&(_fp->_lock->mutex)); \
  _IO_cleanup_region_end (0)
#else
# define _IO_acquire_lock(_fp) \
	_IO_cleanup_region_start ((void (*) (void *)) _IO_funlockfile, (_fp));      \
  if (__pthread_mutex_init != ((void *)0)) __pthread_mutex_lock(&(_fp->_lock->mutex))

# define _IO_release_lock(_fp) \
  if (__pthread_mutex_init != ((void *)0)) __pthread_mutex_unlock (&(_fp->_lock->mutex)); \
  _IO_cleanup_region_end (0)
#endif
#else
# define _IO_acquire_lock(_fp) \
	_IO_cleanup_region_start ((void (*) (void *)) _IO_funlockfile, (_fp));   

# define _IO_release_lock(_fp) \
  _IO_cleanup_region_end (0)
#endif

static FILE *_pure_head = NULL;

#define _pure_magic(stream) (((stream)->_flags & _IO_MAGIC_MASK) == _IO_MAGIC)

static int _pure_fflush(FILE *stream) {
	int rv=0;
	if (stream->_flags & _IO_CURRENTLY_PUTTING) {
		int n=stream->_IO_write_ptr-stream->_IO_write_base;
		if (n>0) {
			if(write(stream->_fileno,stream->_IO_write_base,n) != n)
				rv=EOF;
		}
		stream->_flags &= ~_IO_CURRENTLY_PUTTING;
		stream->_IO_write_ptr=stream->_IO_write_base=stream->_IO_write_end=NULL;
	} else {
		int n=stream->_IO_read_end-stream->_IO_read_ptr;
		if (n>0) {
			if (lseek64(stream->_fileno,-n,SEEK_CUR) == -1)
				rv=EOF;
		}
		stream->_IO_read_ptr=stream->_IO_read_base=stream->_IO_read_end=NULL;
	}
	return rv;
}

static int _pure_fgetc (FILE *stream){
	char c;
	{
		if (stream->_flags & _IO_IN_BACKUP) {
			stream->_flags &= ~_IO_IN_BACKUP;
			return stream->_shortbuf[0];
		} else {
			if (stream->_flags & _IO_UNBUFFERED) { /* unbuffered */
				int n;
				if ((n=read(stream->_fileno,&c,1)) < 1) {
					if (n==0)
						stream->_flags |= _IO_EOF_SEEN;
					else
						stream->_flags |= _IO_ERR_SEEN;
					return EOF;
				} else
					return c;
			} else { /* line or block buffered */
				if (stream->_IO_buf_base == NULL) {
					stream->_IO_buf_base=malloc(BUFSIZ);
					if (stream->_IO_buf_base != NULL)
						stream->_IO_buf_end=stream->_IO_buf_base+BUFSIZ;
					if (isatty(stream->_fileno))
							stream->_flags |= _IO_LINE_BUF;
				}
				if (stream->_flags & _IO_CURRENTLY_PUTTING) {
					if (_pure_fflush(stream) == EOF) {
						stream->_flags |= _IO_ERR_SEEN;
						return EOF;
					}
				}
				if (stream->_flags & _IO_LINE_BUF) {  /* line buffered */
					if (stream->_IO_read_ptr >= stream->_IO_read_end) {
						int loaded=0;
						int len=stream->_IO_buf_end-stream->_IO_buf_base;
						int n;
						do {
							if ((n=read(stream->_fileno,stream->_IO_buf_base+loaded, len-loaded)) < 1) {
								if (n==0)
									stream->_flags |= _IO_EOF_SEEN;
								else {
									stream->_flags |= _IO_ERR_SEEN;
									return EOF;
								}
							}
							loaded += n;
						} while (n > 0 && loaded < len && !memchr(stream->_IO_buf_base,'\n',loaded));
						if (n<=0 && loaded==0) 
							return EOF;
						stream->_IO_read_ptr=stream->_IO_read_base=stream->_IO_buf_base;
						stream->_IO_read_end=stream->_IO_buf_base+loaded;
					}
					c=*(stream->_IO_read_ptr++);
				} else { /* block buffered */
					if (stream->_IO_read_ptr >= stream->_IO_read_end) {
						int n;
						if ((n=read(stream->_fileno,stream->_IO_buf_base,
								stream->_IO_buf_end-stream->_IO_buf_base)) < 1) {
							if (n==0)
								stream->_flags |= _IO_EOF_SEEN;
							else
								stream->_flags |= _IO_ERR_SEEN;
							return EOF;
						}
						stream->_IO_read_ptr=stream->_IO_read_base=stream->_IO_buf_base;
						stream->_IO_read_end=stream->_IO_buf_base+n;
					}
					c=*(stream->_IO_read_ptr++);
				}
				return c;
			}
		}
	}
}

static int _pure_fputc (int c, FILE *stream){
	char ch=c;
	if (stream->_flags & _IO_UNBUFFERED) { /*unbuffered*/
		if (write(stream->_fileno,&ch,1) < 1) {
			stream->_flags |= _IO_ERR_SEEN;
			return EOF;
		} else
			return c;
	} else { /* line or block buffered */
		if (stream->_IO_buf_base == NULL) {
			stream->_IO_buf_base=malloc(BUFSIZ);
			if (stream->_IO_buf_base != NULL)
				stream->_IO_buf_end=stream->_IO_buf_base+BUFSIZ;
			if (isatty(stream->_fileno))
				 stream->_flags |= _IO_LINE_BUF;
		}
		if (!(stream->_flags & _IO_CURRENTLY_PUTTING)) {
			if (_pure_fflush(stream) == EOF) {
				stream->_flags |= _IO_ERR_SEEN;
				return EOF;
			}
			stream->_flags |= _IO_CURRENTLY_PUTTING;
		}
		if (stream->_flags & _IO_LINE_BUF) { /* line buffered */
			if (stream->_IO_write_ptr >= stream->_IO_buf_end) {
				if (_pure_fflush(stream) == EOF) {
					stream->_flags |= _IO_ERR_SEEN;
					return EOF;
				}
				stream->_flags |= _IO_CURRENTLY_PUTTING;
			}
			if (stream->_IO_write_ptr == NULL)
				stream->_IO_write_ptr=stream->_IO_write_base=stream->_IO_write_end=stream->_IO_buf_base;
			*(stream->_IO_write_ptr++)=c;
			if (c=='\n') {
				if (_pure_fflush(stream) == EOF) {
					stream->_flags |= _IO_ERR_SEEN;
					return EOF;
				}
				stream->_flags |= _IO_CURRENTLY_PUTTING;
				stream->_IO_write_ptr=stream->_IO_write_base=stream->_IO_write_end=stream->_IO_buf_base;
			}
		} else { /* block buffered */
			if (stream->_IO_write_ptr >= stream->_IO_write_end) {
				if (_pure_fflush(stream) == EOF) {
					stream->_flags |= _IO_ERR_SEEN;
					return EOF;
				}
				stream->_flags |= _IO_CURRENTLY_PUTTING;
				stream->_IO_write_ptr=stream->_IO_write_base=stream->_IO_buf_base;
				stream->_IO_write_end=stream->_IO_buf_end;
			}
			*(stream->_IO_write_ptr++)=c;
		}
		return c;
	}
}

int __underflow (FILE *s){
	return _pure_fgetc(s);
}

int __uflow (FILE *s){
	return _pure_fgetc(s);
}

int __overflow (FILE *s, int c){
	_pure_fputc(c,s);
}

static int _pure_parse_mode(const char *modes) {
	int flags=0;
	while (*modes) {
		switch (*modes) {
			case 'r':flags=O_RDONLY;break;
			case 'w':flags=O_WRONLY|O_CREAT|O_TRUNC;break;
			case 'a':flags=O_WRONLY|O_CREAT|O_APPEND;break;
			case '+':flags &= ~(O_WRONLY | O_RDONLY); flags |= O_RDWR;break;
		}
		modes++;
	}
	return flags;
}

static FILE *_pure_assign_file(int fd, int oflags, FILE *new) {
	new->_fileno=fd;
	new->_flags=_IO_MAGIC|_IO_IS_FILEBUF;
	new->_offset=0;
#ifdef _IO_MTSAFE_IO
	if (new->_lock == NULL) {
		new->_lock=malloc(sizeof(_IO_lock_t));
		_IO_lock_init(*(((_IO_lock_t *)(new->_lock))));
	}
#endif
	if (oflags & O_RDONLY) new->_flags |= _IO_NO_WRITES;
	if (oflags & O_WRONLY) new->_flags |= _IO_NO_READS;
	if (oflags & O_APPEND) new->_flags |= _IO_IS_APPENDING;
	return new;
}

static FILE *_pure_new_file(int fd, int oflags, int fdopen) {
	FILE *new=(FILE *)malloc(sizeof(FILE));
	if (new == NULL) {
		if (!fdopen) close(fd);
		return NULL;
	} else {
		memset(new,0,sizeof(FILE));
		new->_IO_buf_base=malloc(BUFSIZ);
		if (new->_IO_buf_base == NULL) {
			if (!fdopen) close(fd);
			free(new);
			return NULL;
		} else {
			new->_IO_buf_end=new->_IO_buf_base+BUFSIZ;
			new->_chain=_pure_head;
			_pure_head=new;
			return _pure_assign_file(fd,oflags,new);
		}
	}
}

static FILE *_pure_fopen (const char *filename, int flags){
	int fd;
	/*write(2,"FO",2);
	write(2,filename,strlen(filename));
	write(2,"\n",1);*/
	if ((fd=open(filename,flags,0666)) < 0)
		return NULL;
	else
		return _pure_new_file(fd, flags, 0);
}

FILE *fopen (const char *filename, const char *modes){
	return _pure_fopen(filename, _pure_parse_mode(modes));
}

FILE *fopen64 (const char *filename, const char *modes){
	return _pure_fopen(filename, _pure_parse_mode(modes)|O_LARGEFILE);
}

static FILE *_pure_freopen (const char *filename, int flags, FILE *stream){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EINVAL;
	} else {
		_IO_acquire_lock(stream);
		int fd;
		_pure_fflush(stream);
		close(stream->_fileno);
		if ((fd=open(filename,flags,0666)) >= 0) 
			_pure_assign_file(fd,flags,stream);
		_IO_release_lock(stream);
	}
	return stream;
}

FILE *freopen (const char *filename, const char *modes, FILE *stream){
	return _pure_freopen(filename, _pure_parse_mode(modes), stream);
}

FILE *freopen64 (const char *filename, const char *modes, FILE *stream){
	return _pure_freopen(filename, _pure_parse_mode(modes)|O_LARGEFILE, stream);
}

/* recursive is simpler - to be changed into iteration */
static int _pure_del_stream(FILE *s, FILE **h)
{
	if (*h) {
		if (s == *h) {
			*h = s->_chain;
			return 1;
		} else
			return _pure_del_stream(s,&((*h)->_chain));
	} else
		return 0;
}

int fclose(FILE *stream){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EINVAL;
		return -1;
	} else {
		int fd;
		int tofree;
		_IO_acquire_lock(stream);
		_pure_fflush(stream);
		close(stream->_fileno);
		if (!(stream->_flags & _IO_USER_BUF)) free (stream->_IO_buf_base);
		tofree=_pure_del_stream(stream,&_pure_head);
		_IO_release_lock(stream);
#ifdef _IO_MTSAFE_IO
		if (stream->_lock != NULL)
			_IO_lock_fini(*(((_IO_lock_t *)(stream->_lock))));
#endif
		if (tofree) {
#ifdef _IO_MTSAFE_IO
			free(stream->_lock);
#endif
			free(stream);
		}
		return 0;
	}
}

FILE *fdopen (int fd, const char *modes){
	int flags=_pure_parse_mode(modes);
	return _pure_new_file(fd, flags, 1);
}

#define _CL_IO_MODE_MASK ~(_IO_UNBUFFERED | _IO_LINE_BUF)
int setvbuf (FILE *stream, char *buf, int modes, size_t n) {
	int userbuf=(buf != NULL);
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EINVAL;
		return -1;
	} else {
		if (buf == NULL && n > 0 && (buf=malloc(n)) == NULL) 
			return -1;
		else {
			int rv=0;
			_IO_acquire_lock(stream);
			if (buf != NULL) {
				if (stream->_flags & _IO_USER_BUF) free (stream->_IO_buf_base);
				if (userbuf)
					stream->_flags |= _IO_USER_BUF;
				else
					stream->_flags &= ~_IO_USER_BUF;
				stream->_IO_buf_base=buf;
				stream->_IO_buf_end=buf+n;
				/*pointers*/
			} 
			switch (modes) {
				case _IONBF: stream->_flags = (stream->_flags & _CL_IO_MODE_MASK) | _IO_UNBUFFERED; 
										 break;
				case _IOLBF: stream->_flags = (stream->_flags & _CL_IO_MODE_MASK) | _IO_LINE_BUF;
										 break;
				case _IOFBF: stream->_flags =  (stream->_flags & _CL_IO_MODE_MASK);
										 break;

				default:
										 rv= -1;
										 break;
			}
			_IO_release_lock(stream);
			return rv;
		}
	}
}

void setbuf (FILE *stream, char *buf){
	setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}

void setbuffer(FILE *stream, char *buf, size_t size){
	setvbuf(stream, buf, buf ? _IOFBF : _IONBF, size);
}

void setlinebuf(FILE *stream){
	setvbuf(stream, (char *)NULL, _IOLBF, 0);
}

int vfprintf(FILE *stream, const char *format, va_list ap){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return -1;
	} else {
		char *s;
		int rv;
		rv=vasprintf(&s, format, ap);
		if (rv>0)
			rv=fputs(s,stream);
		free(s);
		return rv;
	}
}

int vprintf(const char *format, va_list ap){
	return vfprintf(stdout,format,ap);
}

int fprintf (FILE *stream, const char *format, ...){
	int rv;
	va_list ap;
	va_start(ap, format);
	rv=vfprintf(stream,format,ap);
	va_end(ap);
	return rv;
}

int printf (const char *format, ...){
	int rv;
	va_list ap;
	va_start(ap, format);
	rv=vfprintf(stdout,format,ap);
	va_end(ap);
	return rv;
}

int vfscanf(FILE *stream, const char *format, va_list ap) {
	struct arg_scanf {
		void *data;
		int (*getch)(FILE *);
		int (*putch)(int,FILE *);
	} as={stream,  fgetc, ungetc};

	return __v_scanf(&as,format,ap);
}

int vscanf(const char *format, va_list ap){
	return vfscanf(stdin,format,ap);
}

int fscanf (FILE *stream, const char *format, ...){
	int rv;
	va_list ap;
	va_start(ap, format);
	rv=vfscanf(stream,format,ap);
	va_end(ap);
	return rv;
}

int scanf (const char *format, ...){
	int rv;
	va_list ap;
	va_start(ap, format);
	rv=vfscanf(stdin,format,ap);
	va_end(ap);
	return rv;
}

int fflush(FILE *stream) {
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return 0;
	} else
		return _pure_fflush(stream);
}

int fflush_unlocked (FILE *stream){
	return _pure_fflush(stream);
}

int fgetc_unlocked (FILE *stream){
	if (stream->_flags & _IO_NO_READS) {
		stream->_flags |= _IO_ERR_SEEN;
		return 0;
	} else
		return _pure_fgetc (stream);
}

int fgetc (FILE *stream){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return 0;
	} else {
		int rv;
		_IO_acquire_lock(stream);
		rv=fgetc_unlocked(stream);
		_IO_release_lock(stream);
		return rv;
	}
}

int getc (FILE *stream){
	return fgetc(stream);
}

int getchar (void){
	return fgetc(stdin);
}

int getc_unlocked (FILE *stream){
	return fgetc_unlocked(stream);
}

int getchar_unlocked (void){
	return fgetc_unlocked(stdin);
}

int fputc_unlocked (int c, FILE *stream){
	if (stream->_flags & _IO_NO_WRITES) {
		stream->_flags |= _IO_ERR_SEEN;
		return 0;
	} else
		return _pure_fputc (c,stream);
}

int fputc (int c, FILE *stream){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return 0;
	} else {
		int rv;
		_IO_acquire_lock(stream);
		rv=fputc_unlocked(c,stream);
		_IO_release_lock(stream);
		return rv;
	}
}

int putc (int c, FILE *stream){
	return fputc(c,stream);
}

int putchar (int c){
	/*char buf[]="PCx\n";
	buf[2]=c;
	write (2,buf,4);*/
	return fputc(c,stdout);
}

int putc_unlocked (int c, FILE *stream){
	return fputc_unlocked(c,stream);
}

int putchar_unlocked (int c){
	/*char buf[]="PUx\n";
	buf[2]=c;
	write (2,buf,4);*/
	return fputc_unlocked(c,stdout);
}

char *fgets_unlocked (char *buf, int n, FILE *stream){
	int c=0;
	char *s=buf;
	while (n>1 && c != EOF && c != '\n') {
		if ((c=_pure_fgetc(stream)) != EOF) {
			*s=c;
			s++;
			n--;
		}
		*s=0;
	}
	if (s==buf && stream->_flags & _IO_EOF_SEEN)
		return NULL;
	else
		return buf;
}

char *fgets (char *buf, int n, FILE *stream){
	char *rv;
	_IO_acquire_lock(stream);
	rv=fgets_unlocked(buf,n,stream);
	_IO_release_lock(stream);
	return rv;
}

char *gets (char *s){
	return fgets(s,__INT_MAX__,stdin);
}

int fputs_unlocked (const char *s, FILE *stream){
	return fwrite_unlocked(s,1,strlen(s),stream);
}

int fputs(const char *s, FILE *stream){
	int rv;
	_IO_acquire_lock(stream);
	rv=fputs_unlocked(s,stream);
	_IO_release_lock(stream);
	return rv;
}

int puts (const char *s){
	return fputs(s,stdout)+fputc('\n',stdout);
}

int ungetc (int c, FILE *stream){
	if (!stream || !_pure_magic(stream) || (stream->_flags & _IO_IN_BACKUP) ||
			(stream->_flags & _IO_UNBUFFERED) || c<0 || c>255)
		return EOF;
	else {
		stream->_flags |= _IO_IN_BACKUP;
		stream->_shortbuf[0]=c;
		stream->_flags &= ~(_IO_ERR_SEEN | _IO_EOF_SEEN);
		return c;
	}
}

size_t fread_unlocked (void *ptr, size_t size, size_t n, FILE *stream){
	char *cptr = (char *) ptr;
	int len=size*n;
	int rv;
	if (!n || len/n!=size) return 0;
	if (stream->_flags & _IO_NO_READS) {
		stream->_flags |= _IO_ERR_SEEN;
		return 0;
	} 
	if (stream->_flags & _IO_UNBUFFERED) {
		rv=read(stream->_fileno,ptr,len);
	} else {
		int i,c=0;
		for (i=0,rv=0; i<len && c!= EOF; i++,rv++)
			if ((c=_pure_fgetc(stream)) != EOF)
				cptr[i]=c;
	}
	return size?rv/size:0;
};

size_t fread (void *ptr, size_t size, size_t n, FILE *stream){
	int rv;
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return 0;
	}
	_IO_acquire_lock(stream);
	rv=fread_unlocked(ptr,size,n,stream);
	_IO_release_lock(stream);
	return rv;
}

size_t fwrite_unlocked (const void *ptr, size_t size, size_t n, FILE *s){
	char *cptr = (char *) ptr;
	int len=size*n;
	int rv;
	/*write(2,"FWU ",4);
	write(2,ptr,len);
	write(2,"\n",1);*/
	if (!n || len/n!=size) return 0;
	if (s->_flags & _IO_NO_WRITES) {
		s->_flags |= _IO_ERR_SEEN;
		return 0;
	} 
	if (s->_flags & _IO_UNBUFFERED) {
		rv=write(s->_fileno,ptr,len);
	} else {
		int i,c=0;
		for (i=0,rv=0; i<len && c!= EOF; i++,rv++)
			_pure_fputc(cptr[i],s);
	}
	return size?rv/size:0;
}

size_t fwrite (const void *ptr, size_t size, size_t n, FILE *stream){
	int rv;
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return 0;
	}
	_IO_acquire_lock(stream);
	fwrite_unlocked(ptr,size,n,stream);
	_IO_release_lock(stream);
}

static int _pure_fseek (FILE *stream, __off64_t off, int whence){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return -1;
	} else {
		__off64_t rv;
		_pure_fflush(stream);
		stream->_flags &= ~(_IO_ERR_SEEN | _IO_EOF_SEEN);
		/* pointers */
		rv=lseek64(stream->_fileno,off,whence);
		return (rv == -1)?-1:0;
	}
}

__off64_t _pure_ftell (FILE *stream){
	if (stream == NULL || !_pure_magic(stream)) {
		errno=EBADF;
		return -1;
	} else {
		__off64_t rv=0;
		_pure_fflush(stream);
		rv=lseek64(stream->_fileno,rv,SEEK_CUR);
		if (rv != -1) 
			if (stream->_flags & _IO_IN_BACKUP) rv--;
		return rv;
	}
}

int fseek (FILE *stream, long int off, int whence){
	return _pure_fseek(stream, (__off64_t) off, whence);
}

long int ftell (FILE *stream){
	return (long int) _pure_ftell(stream);
}

int fseeko (FILE *stream, __off_t off, int whence){
	return _pure_fseek(stream, (__off64_t) off, whence);
}

__off_t ftello (FILE *stream){
	return (__off_t) _pure_ftell(stream);
}

int fseeko64 (FILE *stream, __off64_t off, int whence){
	return _pure_fseek(stream, off, whence);
}

__off64_t ftello64 (FILE *stream){
	return _pure_ftell(stream);
}

void rewind (FILE *stream){
	fseek(stream, 0L, SEEK_SET);
}

int fsetpos (FILE *stream, const fpos_t *pos){
	return _pure_fseek(stream, (__off64_t) pos->__pos, SEEK_SET);
}

int fgetpos (FILE *stream, fpos_t *pos){
	__off64_t rv=_pure_ftell(stream);
	if (rv == -1) 
		return -1;
	else {
		pos->__pos = (__off_t) rv;
		return 0;
	}
}

int fsetpos64 (FILE *stream, const fpos64_t *pos){
	return _pure_fseek(stream, (__off64_t) pos->__pos, SEEK_SET);
}

int fgetpos64 (FILE *stream, fpos64_t *pos){
	__off64_t rv=_pure_ftell(stream);
	if (rv == -1) 
		return -1;
	else {
		pos->__pos = rv;
		return 0;
	}
}

void clearerr_unlocked (FILE *stream) {
	stream->_flags &= ~(_IO_ERR_SEEN | _IO_EOF_SEEN);
}

void clearerr (FILE *stream){
	if (stream != NULL && _pure_magic(stream)) {
		clearerr_unlocked(stream);
	}
}

int feof_unlocked (FILE *stream) {
	return (stream->_flags & _IO_EOF_SEEN);
}

	int feof (FILE *stream){
		if (stream == NULL || !_pure_magic(stream)) 
			return -1;
		else {
			int rv;
			_IO_acquire_lock(stream);
			rv=feof_unlocked(stream);
			_IO_release_lock(stream);
			return rv;
		}
	}

int ferror_unlocked (FILE *stream) {
	return (stream->_flags & _IO_ERR_SEEN);
}

	int ferror (FILE *stream){
		if (stream == NULL || !_pure_magic(stream)) 
			return -1;
		else {
			int rv;
			_IO_acquire_lock(stream);
			rv=ferror_unlocked(stream);
			_IO_release_lock(stream);
			return rv;
		}
	}

int fileno_unlocked (FILE *stream) {
	return stream->_fileno;
}

int fileno (FILE *stream){
	/*char buf[]="FNOxx\n";
	buf[3]=(stream == NULL)?'X':'-';
	buf[4]=(!_pure_magic(stream))?'X':'-';
	write (2,buf,6);*/
	if (stream == NULL || !_pure_magic(stream)) 
		return -1;
	else {
		int rv;
		_IO_acquire_lock(stream);
		rv=fileno_unlocked(stream);
		_IO_release_lock(stream);
		return rv;
	}
}

void flockfile (FILE *stream){
}

int ftrylockfile (FILE *stream){
}

void funlockfile (FILE *stream){
}

FILE *tmpfile (void){
	int fd;
	char template[20] = "/tmp/tmpfile-XXXXXX";
	if ((fd=mkstemp(template))<0)
		return 0;
	else {
		unlink(template);
		return _pure_new_file(fd, O_RDWR, 0);
	}
}

FILE *tmpfile64 (void){
	int fd;
	char template[20] = "/tmp/tmpfile-XXXXXX";
	if ((fd=mkstemp(template))<0)
		return 0;
	else {
		unlink(template);
		return _pure_new_file(fd, O_RDWR | O_LARGEFILE, 0);
	}
}

int getw(FILE *stream) {
	int w;
	if (fread ((void *) &w, sizeof (w), 1, stream) != 1)
		return EOF;
	else
		return w;
}

	int putw(int w, FILE *stream) {
		if (fwrite ((const void *) &w, sizeof (w), 1, stream) < 1)
			return EOF;
		else
			return 0;
	}

#define GETDELIM_SIZE 256
static size_t getdelim_unlocked (char **lineptr, size_t *n, int delim, FILE *stream) {
	int c=0;
	int count=0;
	int size;
	char *s=*lineptr;
	if (*lineptr=NULL) *n=0;
	size=*n;
	while (c != EOF && c != delim) {
		if ((c=_pure_fgetc(stream)) != EOF) {
			if (count+1 >= size) {
				*lineptr=realloc(*lineptr,size+GETDELIM_SIZE);
				size += GETDELIM_SIZE;
				(*lineptr)[count]=c;
				count++;
			}
			(*lineptr)[count]=0;
			count++;
		}
	}
	if (count > *n) {
		*lineptr=realloc(*lineptr,count);
		*n=count;
	}
	return count;
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
	int rv;
	_IO_acquire_lock(stream);
	rv=getdelim_unlocked(lineptr,n,delim,stream);
	_IO_release_lock(stream);
	return rv;
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream){
	return getdelim(lineptr,n,'\n',stream);
}
