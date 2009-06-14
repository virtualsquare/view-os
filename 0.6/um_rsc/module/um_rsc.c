/*   
 *   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   um_rsc.c: UMView Remote System Call module 
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "gdebug.h"

#include "module.h"
#include "parse_args.h"
#include "utils.h"

#include "rsc_client.h"


#include "handshake.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "8050"
#define SERVER_PORT_EVENT_SUB "8051"

static struct service s;
static int event_sub_fd;
static struct reg_cbs *reg_cbs;

static int create_fd(char *server_name, char *port_number) {
  struct addrinfo hint, *res;
  int fd, ret;
  
  GDEBUG(1, "Server name = %s, port number = %s\n", server_name, port_number);
  /* I get the info about "server_name" */
  bzero(&hint, sizeof(hint));
  hint.ai_socktype = SOCK_STREAM;
  if( (ret = getaddrinfo(server_name, port_number, &hint, &res)) != 0) {
    GERROR("Getaddrinfo() error: %s\n", gai_strerror(ret));
    return -1;
  }

  /* I connect the client */
  if( (fd = socket(res->ai_family, res->ai_socktype, 0)) == -1 ) {
    GERROR("Socket() error: %s\n", strerror(errno));
    return -1;
  }

  if( connect(fd, res->ai_addr, res->ai_addrlen) != 0 ) {
    GERROR("Connect() error: %s\n", strerror(errno));
    return -1;
  }

#ifdef GDEBUG_ENABLED
  {
    char str_addr[INET6_ADDRSTRLEN];
    void *src;
    int port;
    
    if(res->ai_family == AF_INET) {
      src = &( (struct sockaddr_in *)(res->ai_addr) )->sin_addr;
      port = ( (struct sockaddr_in *)(res->ai_addr) )->sin_port;
    } else {
      src = &( (struct sockaddr_in6 *)(res->ai_addr) )->sin6_addr;
      port = ( (struct sockaddr_in6 *)(res->ai_addr) )->sin6_port;
    }
    
    GDEBUG(1, "Connected to < %s, %d >", 
        inet_ntop(res->ai_family, src, str_addr, INET6_ADDRSTRLEN), 
        ntohs(port));
  }
#endif
  freeaddrinfo(res);

  return fd;
}

static int init_client(char *server_name, char *port_number, char *event_sub_port_number) {
  int fd,  nwrite, nread;
  struct handshake req, resp;
  enum arch my_arch, server_arch;

  /* I'm connecting to server */
  fd = create_fd(server_name, port_number);
  if(fd == -1) {
    GERROR("I cannot connect to the server\n");
    return -1;
  }

  /* I'm connecting to server's event subscribe port */
  event_sub_fd = create_fd(server_name, event_sub_port_number);
  if(event_sub_fd == -1) {
    GERROR("I cannot connect to the event subscribe service\n");
    return -1;
  }

  /* I get my architecture and I send it to the server */ 
  if((my_arch = aconv_get_host_arch()) == ACONV_ARCH_ERROR) {
    GERROR("I cannot get my architecture\n");
    return -1;
  }

  GDEBUG(1, "My architecture is %s (%d)\n", aconv_arch2str(my_arch), my_arch);
  req.arch = htonl(my_arch);
  GDEBUG(1, "req.arch = %d\n", req.arch);

  nwrite = write_n_bytes(fd, &req, sizeof(req));
  if(nwrite != sizeof(req)) {
    GERROR("I cannot send my architecture to the server.\n");
    return -1;
  }

  nread = read_n_bytes(fd, &resp, sizeof(resp));
  if(nread != sizeof(resp)) {
    GERROR("I cannot read the server architecture.\n");
    return -1;
  }
  
  server_arch = ntohl(resp.arch);
  GDEBUG(1, "Server architecture is %s\n", aconv_arch2str(server_arch));

  if(rscc_init(fd, event_sub_fd, &reg_cbs, my_arch, server_arch) == -1) {
    GERROR("I cannot initialize the RSC module.\n");
    return -1;
  }
  return fd;
  
}

static epoch_t rsc_checkfun(int type, void *arg) {
  if( type == CHECKSOCKET) {
    return 1;
  } else if(type == CHECKPATH) {
    char *path = arg;
    /* I don't manage the /lib /usr/lib directories, in this way the program use the shared
     * library of the UMView host. I don't manage the /bin and /usr/bin directories 
     * in this way I can execute local program and not remote ones. */
    /* printf("path = '%s' is for us? %d\n", path, (strncmp(path, "/lib", 4) != 0 && strncmp(path, "/bin", 4) != 0)); */
    return (strncmp(path, "/lib", 4) != 0 &&
        strncmp(path, "/bin", 4) != 0);
  } else if(type == CHECKIOCTLPARMS) {
    return rscc_check_ioctl_request(((struct ioctl_len_req *)arg)->req);
  } else {
    /* GDEBUG(1, "rsc_path: it's not for us!\n"); */
    return 0;
  }

}

static long rsc_event_subscribe(void (* cb)(), void *arg, int fd, int how) {
  int ret;
  ret = rscc_es_send_req(reg_cbs, event_sub_fd, fd, how, cb, arg);
  if(ret == -1) {
    GDEBUG(1, "Error adding fd = %d; how = %d; cb = %p; arg = %p\n", fd, how, cb, arg);
    return -1;
  }
  GDEBUG(1, "rsc_event_subscribe: added fd = %d, how = %d, cb = %p, arg = %p\n", fd, how, cb, arg);
  
  return ret;
}

void _um_mod_init(char *initargs) {
  char *server_addr;
  char *server_port;
  char *event_sub_server_port;
  int opt_len;
  int ret;
  struct rsc_option opt[] = {
    {"sa", 1, &server_addr},
    {"sp", 1, &server_port},
    {"essp", 1, &event_sub_server_port}
  };
  
  /* Parsing of the initialization arguments */
  server_addr = SERVER_ADDR;
  server_port = SERVER_PORT;
  event_sub_server_port = SERVER_PORT_EVENT_SUB;

  opt_len = sizeof(opt) / sizeof(struct rsc_option);
  if( (ret = rsc_parse_opt(initargs, opt, opt_len)) != 0 ) {
    /* Some problems occurred during the parsing of the init args */
    GERROR("Bad initialization arguments: %s\n", rsc_parse_to_string(ret));
    return;
  }
  
  /* Connection to the server */
  if( init_client(server_addr, server_port, event_sub_server_port) < 0) {
    GERROR("Connect_to_server() error\n");
    return;
  }

  /* If the control reaches here, the connection was successful and
   * I can start to fill the struct service. */
	s.name = "Remote System Call";
	s.code = 0xF9;
	
	s.checkfun = rsc_checkfun; 
  s.event_subscribe = rsc_event_subscribe;
  s.syscall = (sysfun *) calloc(scmap_scmapsize, sizeof(sysfun));
	s.socket = (sysfun *) calloc(scmap_sockmapsize, sizeof(sysfun));
  
  SERVICESYSCALL(s, fcntl, rscc_fcntl);
  SERVICESYSCALL(s, fcntl64, rscc_fcntl);
  SERVICESYSCALL(s, ioctl, rscc_ioctl);
  
  SERVICESYSCALL(s, access, rscc_access);
  SERVICESYSCALL(s, adjtimex, rscc_adjtimex);
  SERVICESYSCALL(s, chdir, rscc_chdir);
  SERVICESYSCALL(s, chmod, rscc_chmod);
  SERVICESYSCALL(s, chown, rscc_chown);
  SERVICESYSCALL(s, clock_getres, rscc_clock_getres);
  SERVICESYSCALL(s, clock_gettime, rscc_clock_gettime);
  SERVICESYSCALL(s, clock_settime, rscc_clock_settime);
  SERVICESYSCALL(s, close, rscc_close);
  SERVICESYSCALL(s, dup, rscc_dup);
  SERVICESYSCALL(s, dup2, rscc_dup2);
  SERVICESYSCALL(s, fchdir, rscc_fchdir);
  SERVICESYSCALL(s, fchmod, rscc_fchmod);
  SERVICESYSCALL(s, fchown, rscc_fchown);
  SERVICESYSCALL(s, fdatasync, rscc_fdatasync);
  SERVICESYSCALL(s, fgetxattr, rscc_fgetxattr);
  SERVICESYSCALL(s, fsync, rscc_fsync);
  SERVICESYSCALL(s, getdents64, rscc_getdents64);
  SERVICESYSCALL(s, gettimeofday, rscc_gettimeofday);
  SERVICESYSCALL(s, getxattr, rscc_getxattr);
  SERVICESYSCALL(s, lchown, rscc_lchown);
  SERVICESYSCALL(s, lgetxattr, rscc_lgetxattr);
  SERVICESYSCALL(s, link, rscc_link);
  SERVICESYSCALL(s, lseek, rscc_lseek);
  SERVICESYSCALL(s, lstat64, rscc_lstat64);
  SERVICESYSCALL(s, mkdir, rscc_mkdir);
  SERVICESYSCALL(s, mount, rscc_mount);
  SERVICESYSCALL(s, open, rscc_open);
  SERVICESYSCALL(s, pread64, rscc_pread64);
  SERVICESYSCALL(s, pwrite64, rscc_pwrite64);
  SERVICESYSCALL(s, read, rscc_read);
  SERVICESYSCALL(s, readlink, rscc_readlink);
  SERVICESYSCALL(s, rename, rscc_rename);
  SERVICESYSCALL(s, rmdir, rscc_rmdir);
  SERVICESYSCALL(s, setdomainname, rscc_setdomainname);
  SERVICESYSCALL(s, sethostname, rscc_sethostname);
  SERVICESYSCALL(s, settimeofday, rscc_settimeofday);
  SERVICESYSCALL(s, stat64, rscc_stat64);
  SERVICESYSCALL(s, symlink, rscc_symlink);
  SERVICESYSCALL(s, umount2, rscc_umount2);
  SERVICESYSCALL(s, uname, rscc_uname);
  SERVICESYSCALL(s, unlink, rscc_unlink);
  SERVICESYSCALL(s, utime, rscc_utime);
  SERVICESYSCALL(s, utimes, rscc_utimes);
  SERVICESYSCALL(s, write, rscc_write);

  SERVICESOCKET(s, accept, rscc_accept);
  SERVICESOCKET(s, bind, rscc_bind);
  SERVICESOCKET(s, connect, rscc_connect);
  SERVICESOCKET(s, getpeername, rscc_getpeername);
  SERVICESOCKET(s, getsockname, rscc_getsockname);
  SERVICESOCKET(s, getsockopt, rscc_getsockopt);
  SERVICESOCKET(s, listen, rscc_listen);
  SERVICESOCKET(s, recvfrom, rscc_recvfrom);
  SERVICESOCKET(s, sendto, rscc_sendto);
  SERVICESOCKET(s, setsockopt, rscc_setsockopt);
  SERVICESOCKET(s, shutdown, rscc_shutdown);
  SERVICESOCKET(s, socket, rscc_socket);

#if defined __x86_64__
#elif defined __powerpc__
#else
  SERVICESYSCALL(s, chown32, rscc_chown32);
  SERVICESYSCALL(s, lchown32, rscc_lchown32);
  SERVICESYSCALL(s, fchown32, rscc_fchown32);
#endif

#if defined __x86_64__
  SERVICESYSCALL(s, fstat, rscc_fstat64);
  SERVICESYSCALL(s, fstatfs, rscc_fstatfs64);
  SERVICESYSCALL(s, ftruncate, rscc_ftruncate64);
  SERVICESYSCALL(s, truncate, rscc_truncate64);
  SERVICESYSCALL(s, statfs, rscc_statfs64);
#else
  SERVICESYSCALL(s, statfs64, rscc_statfs64);
  SERVICESYSCALL(s, fstat64, rscc_fstat64);
  SERVICESYSCALL(s, fstatfs64, rscc_fstatfs64);
  SERVICESYSCALL(s, ftruncate64, rscc_ftruncate64);
  SERVICESYSCALL(s, truncate64, rscc_truncate64);
  
  SERVICESYSCALL(s, _llseek, rscc__llseek);
  SERVICESOCKET(s, recv, rscc_recv);
  SERVICESOCKET(s, send, rscc_send);
#endif

	add_service(&s);
}

static void
__attribute__ ((constructor))
init (void)
{
  GDEBUG(1, "RSC Init\n");
}
  
static void
__attribute__ ((destructor))
fini (void)
{
  GDEBUG(1, "RSC Fini\n");
}
