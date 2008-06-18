/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   client_server.c: client and server setup functions 
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

int setup_client(char *server_addr, char *server_port) {
  int sockfd;
  struct sockaddr_in client;
  struct addrinfo hints, *res;

  bzero(&hints, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_INET;
  if(getaddrinfo(server_addr, server_port, &hints, &res) != 0) {
    fprintf(stderr, "socket() error: %s\n", strerror(errno));
    return -1;
  }
  sockfd = socket(res->ai_family, res->ai_socktype, 0);
  if(sockfd == -1) {
    fprintf(stderr, "socket() error: %s\n", strerror(errno));
    return -1;
  }

  bzero(&client, sizeof(client));
  client.sin_family = AF_INET;
  client.sin_port = htons(0);
  client.sin_addr.s_addr = INADDR_ANY;
  if(bind(sockfd, (struct sockaddr *)&client, sizeof(client)) == -1) {
    fprintf(stderr, "bind() error: %s\n", strerror(errno));
    return -1;
  }

  if(connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
    fprintf(stderr, "connect() error: %s\n", strerror(errno));
    return -1;
  }

  free(res);
  return sockfd;
}

int setup_server(short int server_port) {
  int sockfd, connfd, optval;
  struct sockaddr_in server, client;
  socklen_t addrlen;

  sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if(sockfd == -1) {
    fprintf(stderr, "socket() error: %s\n", strerror(errno));
    return -1;
  }
  optval = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  bzero(&server, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(server_port);
  server.sin_addr.s_addr = INADDR_ANY;
  if(bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
    fprintf(stderr, "bind() error: %s\n", strerror(errno));
    return -1;
  }

  if(listen(sockfd, 10) == -1) {
    fprintf(stderr, "listen() error: %s\n", strerror(errno));
    return -1;
  }

  addrlen = sizeof(client);
  if((connfd = accept(sockfd, (struct sockaddr *)&client, &addrlen)) == -1) {
    fprintf(stderr, "accept() error: %s\n", strerror(errno));
    return -1;
  }
  return connfd;
}
