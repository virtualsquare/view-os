#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define STDSIZE 4096
struct ramfile {
	struct stat stat;
	size_t maxlen;
	char *buf;
};

#define CTIME 1
#define MTIME 2
#define ATIME 4

static void update_stimes(struct stat *st, int flags)
{
	time_t now;
	time (&now);

	if (flags & CTIME) st->st_ctime = now;
	if (flags & MTIME) st->st_mtime = now;
	if (flags & ATIME) st->st_atime = now;
}

static int ramfile_getattr(const char *path, struct stat *stbuf)
{
	struct ramfile *rf=fuse_get_context()->private_data;

	if(rf != NULL && strcmp(path, "/") == 0) {
		memcpy(stbuf, &rf->stat, sizeof(struct stat));
		return 0;
	} else 
		return -ENOENT;
}

static int ramfile_fgetattr (const char *path, struct stat *stbuf, 
		struct fuse_file_info *fi)
{
	return ramfile_getattr(path,stbuf);
}

static int ramfile_truncate(const char *path, off_t length)
{
	struct ramfile *rf=fuse_get_context()->private_data;
	if(rf ==  NULL || strcmp(path, "/") != 0)
		return -ENOENT;

	if (length > rf->maxlen)
		return -EFBIG;
	
	if (length > rf->stat.st_size)
		memset(&rf->buf[rf->stat.st_size],0,length - rf->stat.st_size);
	rf->stat.st_size = length;
	update_stimes(&rf->stat, ATIME | MTIME);

	return 0;
}

static int ramfile_open(const char *path, struct fuse_file_info *fi)
{
	if(strcmp(path, "/") != 0)
		return -ENOENT;

	/* save flags */
	return 0;
}

static int ramfile_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	size_t len;
	struct ramfile *rf=fuse_get_context()->private_data;

	if(rf == NULL || strcmp(path, "/") != 0)
		return -ENOENT;

	len=rf->stat.st_size;
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, &(rf->buf[offset]), size);
		update_stimes(&rf->stat, ATIME);
	} else
		size = 0;

	return size;
}

static int ramfile_write(const char *path, const char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	size_t len;
	struct ramfile *rf=fuse_get_context()->private_data;

	len=rf->maxlen;
	if (offset < len) { 
		if (offset + size > len)
			size = len - offset;
		memcpy(&(rf->buf[offset]), buf, size);
		if (offset + size > rf->stat.st_size)
			rf->stat.st_size=offset + size;
		update_stimes(&rf->stat, MTIME | ATIME);
	} else
		size = 0;

	return size;
}

static int ramfile_chown(const char *path, uid_t uid, gid_t gid)
{
	struct ramfile *rf=fuse_get_context()->private_data;
	if(rf ==  NULL || strcmp(path, "/") != 0)
		return -ENOENT;
	if (uid != -1)
		rf->stat.st_uid = uid;
	if (gid != -1)
		rf->stat.st_gid = gid;
	return 0;
}

#define CHMOD_MASK (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX)
static int ramfile_chmod(const char *path, mode_t mode)
{
	struct ramfile *rf=fuse_get_context()->private_data;
	if(rf ==  NULL || strcmp(path, "/") != 0)
		return -ENOENT;
	rf->stat.st_mode = (rf->stat.st_mode & ~CHMOD_MASK) | (mode & CHMOD_MASK);
	return 0;
}

static int ramfile_utimens (const char *path, const struct timespec tv[2])
{
	struct ramfile *rf=fuse_get_context()->private_data;
	if(rf ==  NULL || strcmp(path, "/") != 0)
		return -ENOENT;
	rf->stat.st_atime = tv[0].tv_sec;
	rf->stat.st_mtime = tv[1].tv_sec;
  return 0;
}

void *ramfile_init(struct fuse_conn_info *conn)
{
	struct fuse_context *mycontext;
	mycontext=fuse_get_context();
	return mycontext->private_data;
}

static struct fuse_operations ramfile_oper = {
	.init = ramfile_init,
	.getattr	= ramfile_getattr,
	.fgetattr	= ramfile_fgetattr,
	.truncate	= ramfile_truncate,
	.open	= ramfile_open,
	.read	= ramfile_read,
	.write	= ramfile_write,
	.chmod    = ramfile_chmod,
	.chown    = ramfile_chown,
	.utimens    = ramfile_utimens,

};

static void rf_setsize(char *s,struct ramfile *rf)
{
	if (s) {
		long long size=atoi(s);
		while (*s >= '0' && *s <= '9')
			s++;
		switch (*s) {
			case 'k':
			case 'K': size *= 1024; break;
			case 'm':
			case 'M': size *= 1024 * 1024; break;
			case 'g':
			case 'G': size *= 1024 * 1024 * 1024; break;
		}
		rf->maxlen=size;
	}
}

void ramfile_parse_opts(struct ramfile *rf, char *opts)
{
	/* trivial "size" option parse */
	char *sizeptr;
	if ((sizeptr = strstr(opts,"size=")) != NULL)
		rf_setsize(sizeptr+5,rf);
}

int main(int argc, char *argv[])
{
	struct ramfile *rf=calloc(1,sizeof(struct ramfile));
	char *source=argv[argc-2];
	int i;
	int srcfd=-1;
	if (rf == NULL)
		return -ENODEV;
	rf->maxlen=STDSIZE;
	rf->stat.st_mode = S_IFREG | 0666;
	rf->stat.st_nlink = 1;
	rf->stat.st_size = 0;
	if (strcmp(source,"none") != 0) {
		if (stat(source,&(rf->stat)) < 0) {
			free(rf);
			return -ENOENT;
		}
		if (rf->maxlen < rf->stat.st_size)
			rf->maxlen = rf->stat.st_size;
		if ((srcfd = open(source, O_RDONLY)) < 0) {
			free(rf);
			return -EACCES;
		}
	}
	for (i = 0; i < argc-1; i++) {
		if (strcmp(argv[i],"-o")==0)
			ramfile_parse_opts(rf,argv[i+1]);
	}
	rf->buf=malloc(rf->maxlen);
	if (rf->buf == NULL) {
		free(rf);
		if (srcfd >= 0) close(srcfd);
		return -EINVAL;
	}
	if (srcfd >= 0) {
		if ((rf->stat.st_size = read(srcfd, rf->buf, rf->maxlen)) < 0)
			rf->stat.st_size = 0;
		close(srcfd);
	}
	update_stimes(&rf->stat, CTIME | MTIME | ATIME);
	fuse_main(argc, argv, &ramfile_oper, rf);
	free(rf->buf);
	free(rf);

	return 0;
}
