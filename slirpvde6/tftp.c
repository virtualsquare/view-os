/*
 * tftp.c - a simple, read-only tftp server for qemu
 * Copyright (c) 2010 Renzo Davoli 
 * based on tftp.c Copyright (c) 2004 Magnus Damm <damm@opensource.se>
 * 
 * This file is part of SlirpVde6.
 *   
 * SlirpVde6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *        
 * SlirpVde6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *           
 * You should have received a copy of the GNU General Public License
 * along with SlirpVde6.  If not, see <http://www.gnu.org/licenses/>.
 */            

#include "tftp.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "slirpvde6.h"

#define O_BINARY 0

/*
void mdump(void *s, int len)
{
	int i;
	unsigned char *c=s;
	for (i=0;i<len;i++)
		printf("%02x ",c[i]);
	printf("\n");
}
*/

static struct tftp_session tftp_sessions[TFTP_SESSIONS_MAX];

static inline void tftp_session_terminate(struct tftp_session *spt)
{
	if (spt->filename) {
		free(spt->filename);
		if (spt->client_addr)
			free(spt->client_addr);
		spt->filename=NULL;
		spt->client_addr=NULL;
	}
}

static inline int tftp_session_in_use(struct tftp_session *spt)
{
	if ((int)(time(NULL) - spt->timestamp) > 5) 
		tftp_session_terminate(spt);
	return (spt->filename != NULL);
}

static inline void tftp_session_update(struct tftp_session *spt)
{
	spt->timestamp = time(NULL);
}

static int tftp_session_allocate(struct sockaddr *addr, int addrlen)
{
  struct tftp_session *spt;
  int k;

  for (k = 0; k < TFTP_SESSIONS_MAX; k++) {
    spt = &tftp_sessions[k];

    if (!tftp_session_in_use(spt))
        goto found;
  }

  return -1;

 found:
  memset(spt, 0, sizeof(*spt));
	spt->client_addr=malloc(addrlen);
  memcpy(spt->client_addr, addr, addrlen);
	spt->client_addr_len=addrlen;

  tftp_session_update(spt);

  return k;
}

static int tftp_session_find(struct sockaddr *addr, int addrlen)
{
  struct tftp_session *spt;
  int k;

  for (k = 0; k < TFTP_SESSIONS_MAX; k++) {
    spt = &tftp_sessions[k];

    if (tftp_session_in_use(spt)) {
      if (spt->client_addr_len == addrlen &&
					memcmp(spt->client_addr, addr, addrlen)==0) 
				return k;
    }
  }

  return -1;
}

static int tftp_read_data(struct tftp_session *spt, u_int16_t block_nr,
			  u_int8_t *buf, int len)
{
  int fd;
  int bytes_read = 0;

  fd = open(spt->filename, O_RDONLY | O_BINARY);

  if (fd < 0) {
    return -1;
  }

  if (len) {
    lseek(fd, block_nr * 512, SEEK_SET);

    bytes_read = read(fd, buf, len);
  }

  close(fd);

  return bytes_read;
}

static int tftp_send_oack(int fd, struct tftp_session *spt,
                          const char *key, uint32_t value,
                          struct tftp_t *recv_tp)
{
    struct tftp_t tp;
    int n = 0;
		int len;

    memset(&tp, 0, sizeof(tp));

    tp.tp_op = htons(TFTP_OACK);
    n += snprintf((char *)tp.x.tp_buf + n, sizeof(tp.x.tp_buf) - n, "%s",
                  key) + 1;
    n += snprintf((char *)tp.x.tp_buf + n, sizeof(tp.x.tp_buf) - n, "%u",
                  value) + 1;

    len = sizeof(struct tftp_t) - 514 + n;

		lwip_sendto(fd, &tp, len, 0, spt->client_addr, spt->client_addr_len);

    return 0;
}

static void tftp_send_error(int fd, struct tftp_session *spt,
                            u_int16_t errorcode, const char *msg,
                            struct tftp_t *recv_tp)
{
  struct tftp_t tp;
  int nobytes;
	int len;

	memset(&tp, 0, sizeof(tp));

  tp.tp_op = htons(TFTP_ERROR);
  tp.x.tp_error.tp_error_code = htons(errorcode);
  strncpy((char *)tp.x.tp_error.tp_msg, msg, sizeof(tp.x.tp_error.tp_msg));

  len = sizeof(struct tftp_t) - 514 + 3 + strlen(msg);

	lwip_sendto(fd, &tp, len, 0, spt->client_addr, spt->client_addr_len);

out:
  tftp_session_terminate(spt);
}

static int tftp_send_data(int fd, struct tftp_session *spt,
			  u_int16_t block_nr,
			  struct tftp_t *recv_tp)
{
  struct tftp_t tp;
  int nobytes;
	int len;

  if (block_nr < 1) {
    return -1;
  }

  tp.tp_op = htons(TFTP_DATA);
  tp.x.tp_data.tp_block_nr = htons(block_nr);

  nobytes = tftp_read_data(spt, block_nr - 1, tp.x.tp_data.tp_buf, 512);

  if (nobytes < 0) {
    tftp_send_error(fd, spt, 1, "File not found", &tp);
    return -1;
  }

  len = sizeof(struct tftp_t) - (512 - nobytes);

	lwip_sendto(fd, &tp, len, 0, spt->client_addr, spt->client_addr_len);

  if (nobytes == 512) {
    tftp_session_update(spt);
  }
  else {
    tftp_session_terminate(spt);
  }

  return 0;
}

static void tftp_handle_rrq(int fd, struct tftp_t *tp, 
		int pktlen, struct sockaddr  *src, int srclen, char *tftp_prefix)
{
  struct tftp_session *spt;
  int s, k;
  size_t prefix_len;
  char *req_fname;

  /* check if a session already exists and if so terminate it */
  s = tftp_session_find(src, srclen);
  if (s >= 0) {
    tftp_session_terminate(&tftp_sessions[s]);
  }

  s = tftp_session_allocate(src, srclen);

  if (s < 0) {
    return;
  }

  spt = &tftp_sessions[s];

  if (!tftp_prefix || !(*tftp_prefix)) {
      tftp_send_error(fd, spt, 2, "Access violation", tp);
      return;
  }

  /* skip header fields */
  k = 0;
  pktlen -= ((uint8_t *)&tp->x.tp_buf[0] - (uint8_t *)tp);

  /* prepend tftp_prefix */
  prefix_len = strlen(tftp_prefix);
  spt->filename = malloc(prefix_len + TFTP_FILENAME_MAX + 2);
  memcpy(spt->filename, tftp_prefix, prefix_len);
  spt->filename[prefix_len] = '/';

  /* get name */
  req_fname = spt->filename + prefix_len + 1;

  while (1) {
    if (k >= TFTP_FILENAME_MAX || k >= pktlen) {
      tftp_send_error(fd, spt, 2, "Access violation", tp);
      return;
    }
    req_fname[k] = (char)tp->x.tp_buf[k];
    if (req_fname[k++] == '\0') {
      break;
    }
  }

  /* check mode */
  if ((pktlen - k) < 6) {
    tftp_send_error(fd, spt, 2, "Access violation", tp);
    return;
  }

  if (memcmp(&tp->x.tp_buf[k], "octet\0", 6) != 0) {
      tftp_send_error(fd, spt, 4, "Unsupported transfer mode", tp);
      return;
  }

  k += 6; /* skipping octet */

  /* do sanity checks on the filename */
  if (!strncmp(req_fname, "../", 3) ||
      req_fname[strlen(req_fname) - 1] == '/' ||
      strstr(req_fname, "/../")) {
      tftp_send_error(fd, spt, 2, "Access violation", tp);
      return;
  }

  /* check if the file exists */
  if (tftp_read_data(spt, 0, NULL, 0) < 0) {
      tftp_send_error(fd, spt, 1, "File not found", tp);
      return;
  }

  if (tp->x.tp_buf[pktlen - 1] != 0) {
      tftp_send_error(fd, spt, 2, "Access violation", tp);
      return;
  }

  while (k < pktlen) {
      const char *key, *value;

      key = (const char *)&tp->x.tp_buf[k];
      k += strlen(key) + 1;

      if (k >= pktlen) {
	  tftp_send_error(fd, spt, 2, "Access violation", tp);
	  return;
      }

      value = (const char *)&tp->x.tp_buf[k];
      k += strlen(value) + 1;

      if (strcmp(key, "tsize") == 0) {
	  int tsize = atoi(value);
	  struct stat stat_p;

	  if (tsize == 0) {
	      if (stat(spt->filename, &stat_p) == 0)
		  tsize = stat_p.st_size;
	      else {
		  tftp_send_error(fd, spt, 1, "File not found", tp);
		  return;
	      }
	  }

	  tftp_send_oack(fd, spt, "tsize", tsize, tp);
	  return;
      }
  }

  tftp_send_data(fd, spt, 1, tp);
}

static void tftp_handle_ack(int fd, struct tftp_t *tp, 
		int pktlen, struct sockaddr *src, int srclen)
{
  int s;


  s = tftp_session_find(src, srclen);

  if (s < 0) {
    return;
  }

  if (tftp_send_data(fd, &tftp_sessions[s],
		     ntohs(tp->x.tp_data.tp_block_nr) + 1,
		     tp) < 0) {
    return;
  }
}

static void tftp_handle_error(int fd, struct tftp_t *tp, 
		int pktlen, struct sockaddr  *src, int srclen)
{
  int s;

  s = tftp_session_find(src, srclen);

  if (s < 0) {
    return;
  }

  tftp_session_terminate(&tftp_sessions[s]);
}

void tftp_input(int fd, void *arg)
{
  struct tftp_t tp;
	struct sockaddr_in6 src6;
	struct sockaddr *src_addr=(struct sockaddr *)&src6;
	int srclen=sizeof(src6);
	int len=lwip_recvfrom(fd, &tp, sizeof(tp),0,src_addr,&srclen);
	char *tftp_prefix=arg;

  switch(ntohs(tp.tp_op)) {
  case TFTP_RRQ:
    tftp_handle_rrq(fd, &tp, len, src_addr, srclen, tftp_prefix);
    break;

  case TFTP_ACK:
    tftp_handle_ack(fd, &tp, len, src_addr, srclen);
    break;

  case TFTP_ERROR:
    tftp_handle_error(fd, &tp, len, src_addr, srclen);
    break;
  }
}

void tftp_init(struct stack *stack, char *tftp_prefix)
{
	if (tftp_prefix && *tftp_prefix) {
		struct sockaddr_in6 saddr;
		int tftpfd;
		tftpfd=lwip_msocket(stack, PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = htons(69);
		saddr.sin6_addr = in6addr_any;
		lwip_bind(tftpfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
		slirpoll_addfd(tftpfd,tftp_input,tftp_prefix,POLLIN);
	}
}
