/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   rsc_messages.h: messages structure header
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
#ifndef __RSC_MESSAGE_H__
#define __RSC_MESSAGE_H__

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <linux/types.h>
#include <semaphore.h>

/*########################################################################*/
/*##                                                                    ##*/
/*##  REQUESTS/RESPONSE HEADERS                                         ##*/
/*##                                                                    ##*/
/*########################################################################*/
/* Define the common headers used by all request and response messages */
/* The following constant are the values admitted for 'req_type' and 
 * 'resp_type' fields and they are used to multiplex the contents of
 * the message. */
#define RSC_SYS_REQ   1
#define RSC_IOCTL_REQ 2

#define RSC_SYS_RESP   3
#define RSC_IOCTL_RESP 4

#define NO_SYS_CONST 0


/**************************************************************************/
/***  REQUEST                                                           ***/
/**************************************************************************/
/* Used to get the size of a request message */
#define rsc_req_msg_size(req_hdr)  (ntohl((req_hdr)->req_size))
/* The request fields shared by all kind of requests */
#define REQ_HEADER        u_int32_t req_size; int8_t req_type; 
/* The request header structure. It contains only the fields defined by
 * REQ_HEADER constant. */
struct req_header {
  REQ_HEADER
} __attribute__((packed));

/**************************************************************************/
/***  RESPONSE                                                          ***/
/**************************************************************************/
/* Used to get the size of a response message */
#define rsc_resp_msg_size(resp_hdr)  (ntohl((resp_hdr)->resp_size))
/* The response fields shared by all kind of requests */
#define RESP_HEADER       u_int32_t resp_size; int8_t resp_type;
/* The response header structure. It contains only the fields defined by
 * RESP_HEADER constant. */
struct resp_header {
  RESP_HEADER;
} __attribute__((packed));

/*########################################################################*/
/*##                                                                    ##*/
/*##  IOCTL REQUEST MANAGEMENT                                          ##*/
/*##                                                                    ##*/
/*########################################################################*/

/**************************************************************************/
/***  REQUEST                                                           ***/
/**************************************************************************/
/* The ioctl request is used by the client to ask the client if 
 * 'req_ioctl_request' is managed. */
struct ioctl_req_header {
  REQ_HEADER 
  int32_t req_ioctl_request;
} __attribute__((packed));

/**************************************************************************/
/***  RESPONSE                                                          ***/
/**************************************************************************/
/* This message is sent by the server in response to a 'ioctl_req_header'.
 * It contains a single fields ('resp_size_type'), which is a bitmask of
 * two values.
 * The 4 most significant bits inform if the argument is a read,
 * write or read/write argument, the other bits tell the length of that 
 * argument. */
#define IOCTL_R           0x10000000
#define IOCTL_W           0x20000000
#define IOCTL_RW          (IOCTL_R | IOCTL_W)
#define IOCTL_LENMASK     0x0fffffff
#define IOCTL_UNMANAGED   0x40000000

struct ioctl_resp_header {
  RESP_HEADER 
  u_int32_t resp_size_type;
} __attribute__((packed));


/*########################################################################*/
/*##                                                                    ##*/
/*##  SYSCALL EXECUTION REQUEST/RESPONSE                                ##*/
/*##                                                                    ##*/
/*########################################################################*/

/**************************************************************************/
/***  REQUEST                                                           ***/
/**************************************************************************/
/* Define a syscall execution request message for each system call. 
 * Each message has a common field called 'req_rsc_const' that contains
 * the __RSC_* constant to identify the system call. */
#define SYS_REQ_HEADER    REQ_HEADER u_int16_t req_rsc_const;
/* This is a structure representing the common header of all the requests. */
struct sys_req_header {
  SYS_REQ_HEADER
} __attribute__((packed));

/* Now there is the list of all syscall messages */
struct ioctl_req {
  SYS_REQ_HEADER
	int d;
	int request;
	void *arg;
} __attribute__((packed));
 
/* The fcntl syscall can have 2 or 3 arguments and the third argument can have two different types,
 * base on the value of the second argument ('cmd'). The fcntl request use the filed 'cmd_type'
 * to comunicate if the third argument is present and which is its type.  */
#define FCNTL_NO_3RD_ARG    0x01
#define FCNTL_3RD_LONG      0x02
#define FCNTL_3RD_FLOCK     0x04
#define FCNTL_3RD_FLOCK_R   (0x10 | FCNTL_3RD_FLOCK)                /* 0x14  0001 0100 */
#define FCNTL_3RD_FLOCK_W   (0x20 | FCNTL_3RD_FLOCK)                /* 0x24  0010 0100 */
#define FCNTL_3RD_FLOCK_RW  (FCNTL_3RD_FLOCK_R | FCNTL_3RD_FLOCK_W) /* 0x34  0011 0100 */
struct fcntl_req {
  SYS_REQ_HEADER
  int8_t cmd_type;
	int fd;
	int cmd;
  union {
	  long arg;
    struct flock *lock;
  } third;
} __attribute__((packed));

 
struct _llseek_req {
  SYS_REQ_HEADER
	unsigned int fd;
	unsigned long int offset_high;
	unsigned long int offset_low;
	loff_t *result;
	unsigned int whence;
} __attribute__((packed));
 
struct accept_req {
  SYS_REQ_HEADER
	int sockfd;
	struct sockaddr *addr;
	socklen_t *addrlen;
} __attribute__((packed));
 
struct access_req {
  SYS_REQ_HEADER
	char *pathname;
	int mode;
} __attribute__((packed));
 
struct adjtimex_req {
  SYS_REQ_HEADER
	struct timex *buf;
} __attribute__((packed));
 
struct bind_req {
  SYS_REQ_HEADER
	int sockfd;
	struct sockaddr *my_addr;
	socklen_t addrlen;
} __attribute__((packed));
 
struct chdir_req {
  SYS_REQ_HEADER
	char *path;
} __attribute__((packed));
 
struct chmod_req {
  SYS_REQ_HEADER
	char *path;
	mode_t mode;
} __attribute__((packed));
 
struct chown_req {
  SYS_REQ_HEADER
	char *path;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct chown32_req {
  SYS_REQ_HEADER
	char *path;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct clock_getres_req {
  SYS_REQ_HEADER
	clockid_t clk_id;
	struct timespec *res;
} __attribute__((packed));
 
struct clock_gettime_req {
  SYS_REQ_HEADER
	clockid_t clk_id;
	struct timespec *tp;
} __attribute__((packed));
 
struct clock_settime_req {
  SYS_REQ_HEADER
	clockid_t clk_id;
	struct timespec *tp;
} __attribute__((packed));
 
struct close_req {
  SYS_REQ_HEADER
	int fd;
} __attribute__((packed));
 
struct connect_req {
  SYS_REQ_HEADER
	int sockfd;
	struct sockaddr *serv_addr;
	socklen_t addrlen;
} __attribute__((packed));
 
struct dup_req {
  SYS_REQ_HEADER
	int oldfd;
} __attribute__((packed));
 
struct dup2_req {
  SYS_REQ_HEADER
	int oldfd;
	int newfd;
} __attribute__((packed));
 
struct fchdir_req {
  SYS_REQ_HEADER
	int fd;
} __attribute__((packed));
 
struct fchmod_req {
  SYS_REQ_HEADER
	int fildes;
	mode_t mode;
} __attribute__((packed));
 
struct fchown_req {
  SYS_REQ_HEADER
	int fd;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct fchown32_req {
  SYS_REQ_HEADER
	int fd;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct fdatasync_req {
  SYS_REQ_HEADER
	int fd;
} __attribute__((packed));
 
struct fgetxattr_req {
  SYS_REQ_HEADER
	int filedes;
	char *name;
	void *value;
	size_t size;
} __attribute__((packed));
 
struct fstat64_req {
  SYS_REQ_HEADER
	int filedes;
	struct stat64 *buf;
} __attribute__((packed));
 
struct fstatfs64_req {
  SYS_REQ_HEADER
	unsigned int fd;
	struct statfs64 *buf;
} __attribute__((packed));
 
struct fsync_req {
  SYS_REQ_HEADER
	int fd;
} __attribute__((packed));
 
struct ftruncate64_req {
  SYS_REQ_HEADER
	int fd;
	__off64_t length;
} __attribute__((packed));
 
struct getdents64_req {
  SYS_REQ_HEADER
	unsigned int fd;
	struct dirent64 *dirp;
	unsigned int count;
} __attribute__((packed));
 
struct getpeername_req {
  SYS_REQ_HEADER
	int s;
	struct sockaddr *name;
	socklen_t *namelen;
} __attribute__((packed));
 
struct getsockname_req {
  SYS_REQ_HEADER
	int s;
	struct sockaddr *name;
	socklen_t *namelen;
} __attribute__((packed));
 
struct getsockopt_req {
  SYS_REQ_HEADER
	int s;
	int level;
	int optname;
	void *optval;
	socklen_t *optlen;
} __attribute__((packed));
 
struct gettimeofday_req {
  SYS_REQ_HEADER
	struct timeval *tv;
	struct timezone *tz;
} __attribute__((packed));
 
struct getxattr_req {
  SYS_REQ_HEADER
	char *path;
	char *name;
	void *value;
	size_t size;
} __attribute__((packed));
 
struct lchown_req {
  SYS_REQ_HEADER
	char *path;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct lchown32_req {
  SYS_REQ_HEADER
	char *path;
	uid_t owner;
	gid_t group;
} __attribute__((packed));
 
struct lgetxattr_req {
  SYS_REQ_HEADER
	char *path;
	char *name;
	void *value;
	size_t size;
} __attribute__((packed));
 
struct link_req {
  SYS_REQ_HEADER
	char *oldpath;
	char *newpath;
} __attribute__((packed));
 
struct listen_req {
  SYS_REQ_HEADER
	int sockfd;
	int backlog;
} __attribute__((packed));
 
struct lseek_req {
  SYS_REQ_HEADER
	int fildes;
	off_t offset;
	int whence;
} __attribute__((packed));
 
struct lstat64_req {
  SYS_REQ_HEADER
	char *path;
	struct stat64 *buf;
} __attribute__((packed));
 
struct mkdir_req {
  SYS_REQ_HEADER
	char *pathname;
	mode_t mode;
} __attribute__((packed));
 
struct mount_req {
  SYS_REQ_HEADER
	char *source;
	char *target;
	char *filesystemtype;
	unsigned long int mountflags;
	void *data;
} __attribute__((packed));
 
struct open_req {
  SYS_REQ_HEADER
	char *pathname;
	int flags;
} __attribute__((packed));
 
struct pread64_req {
  SYS_REQ_HEADER
	int fd;
	void *buf;
	size_t count;
	off_t offset;
} __attribute__((packed));
 
struct pwrite64_req {
  SYS_REQ_HEADER
	int fd;
	void *buf;
	size_t count;
	off_t offset;
} __attribute__((packed));
 
struct read_req {
  SYS_REQ_HEADER
	int fd;
	void *buf;
	size_t count;
} __attribute__((packed));
 
struct readlink_req {
  SYS_REQ_HEADER
	char *path;
	char *buf;
	size_t bufsiz;
} __attribute__((packed));
 
struct recv_req {
  SYS_REQ_HEADER
	int s;
	void *buf;
	size_t len;
	int flags;
} __attribute__((packed));
 
struct recvfrom_req {
  SYS_REQ_HEADER
	int s;
	void *buf;
	size_t len;
	int flags;
	struct sockaddr *from;
	socklen_t *fromlen;
} __attribute__((packed));
 
struct rename_req {
  SYS_REQ_HEADER
	char *oldpath;
	char *newpath;
} __attribute__((packed));
 
struct rmdir_req {
  SYS_REQ_HEADER
	char *pathname;
} __attribute__((packed));
 
struct send_req {
  SYS_REQ_HEADER
	int s;
	void *buf;
	size_t len;
	int flags;
} __attribute__((packed));
 
struct sendto_req {
  SYS_REQ_HEADER
	int s;
	void *buf;
	size_t len;
	int flags;
	struct sockaddr *to;
	socklen_t tolen;
} __attribute__((packed));
 
struct setdomainname_req {
  SYS_REQ_HEADER
	char *name;
	size_t len;
} __attribute__((packed));
 
struct sethostname_req {
  SYS_REQ_HEADER
	char *name;
	size_t len;
} __attribute__((packed));
 
struct setsockopt_req {
  SYS_REQ_HEADER
	int s;
	int level;
	int optname;
	void *optval;
	socklen_t optlen;
} __attribute__((packed));
 
struct settimeofday_req {
  SYS_REQ_HEADER
	struct timeval *tv;
	struct timezone *tz;
} __attribute__((packed));
 
struct shutdown_req {
  SYS_REQ_HEADER
	int s;
	int how;
} __attribute__((packed));
 
struct socket_req {
  SYS_REQ_HEADER
	int domain;
	int type;
	int protocol;
} __attribute__((packed));
 
struct stat64_req {
  SYS_REQ_HEADER
	char *path;
	struct stat64 *buf;
} __attribute__((packed));
 
struct statfs64_req {
  SYS_REQ_HEADER
	char *path;
	struct statfs64 *buf;
} __attribute__((packed));
 
struct symlink_req {
  SYS_REQ_HEADER
	char *oldpath;
	char *newpath;
} __attribute__((packed));
 
struct truncate64_req {
  SYS_REQ_HEADER
	char *path;
	__off64_t length;
} __attribute__((packed));
 
struct umount2_req {
  SYS_REQ_HEADER
	char *target;
	int flags;
} __attribute__((packed));
 
struct uname_req {
  SYS_REQ_HEADER
	struct utsname *buf;
} __attribute__((packed));
 
struct unlink_req {
  SYS_REQ_HEADER
	char *pathname;
} __attribute__((packed));
 
struct utime_req {
  SYS_REQ_HEADER
	char *filename;
	struct utimbuf *buf;
} __attribute__((packed));
 
struct utimes_req {
  SYS_REQ_HEADER
	char *filename;
	struct timeval tv[2];
} __attribute__((packed));
 
struct write_req {
  SYS_REQ_HEADER
	int fd;
	void *buf;
	size_t count;
} __attribute__((packed));

/**************************************************************************/
/***  REQUEST                                                           ***/
/**************************************************************************/
/* There is a unique syscall execution response for all the syscalls.
 * The informations are:
 * - 'resp_rsc_const': the __RSC_* constant identifying the syscall.
 * - 'resp_retval': the value returned by the syscall
 * - 'resp_errno': the errno value after the execution of the syscall. */
#define SYS_RESP_HEADER   RESP_HEADER u_int16_t resp_rsc_const; int32_t resp_retval; int32_t resp_errno;

struct sys_resp_header {
  RESP_HEADER 
  u_int16_t resp_rsc_const; 
  int32_t resp_retval; 
  int32_t resp_errno;
} __attribute__((packed));

/*########################################################################*/
/*##                                                                    ##*/
/*##  EVENT SUBSCRIPTION                                                ##*/
/*##                                                                    ##*/
/*########################################################################*/
/* The following request are use by the event subscription module, they 
 * differ from the other message because they don't share the same 
 * REQ_HEADER/RESP_HEADER fields */

/* Returns the size of the event subscription message based on the 
 * "event_sub_type" given in input. */
int rsc_es_msg_size(u_int8_t type);


/* The following constant are used to demultiplex the content of this 
 * kind of messages */
enum event_sub_type {
  EVENT_SUB_REQ = 1,
  EVENT_SUB_ACK, 
  EVENT_SUB_RESP,
  EVENT_SUB_DEREG
};

/* These constants are used by the ACK messages */
enum event_sub_ack {
  ACK_NOT_INIT = -1,
  ACK_FD_READY = 1,  /* The fd is ready */
  ACK_FD_REG,     /* The fd was not ready, so is monitored by the server */
  ACK_FD_DEREG_READY, /* The fd was ready and it has been deregistered */
  ACK_FD_DEREG_NOT_READY /* The fd wasn't ready and has been deregistered */
};


/* The request header consists of one field, the 'event_sub_type' constant */
#define RSC_ES_COMMON_FIELDS u_int8_t type;
struct rsc_es_hdr {
  RSC_ES_COMMON_FIELDS
} __attribute__((packed));

/* Used by the client to register a new event at server-side */
struct rsc_es_req {
  RSC_ES_COMMON_FIELDS
  int fd;
  int how;
}__attribute__((packed));

/* Used by the server to ACK a 'rsc_es_req' message. */
struct rsc_es_ack {
  RSC_ES_COMMON_FIELDS
  u_int8_t response;
  int fd;
  int how;
}__attribute__((packed));

/* Used by the server to inform that the event 'how', registered for
 * fd 'fd', was occurred. */
struct rsc_es_resp {
  RSC_ES_COMMON_FIELDS
  int fd;
  int how;
}__attribute__((packed));

/* Used by the client to ask the server to deregister the event 'how'
 * for fd 'fd'. */
struct rsc_es_dereg {
  RSC_ES_COMMON_FIELDS
  int fd;
  int how;
}__attribute__((packed));

#endif /* __RSC_MESSAGE_H__ */
