#ifndef _SLIRPVDE6_H
#define _SLIRPVDE6_H

int slirpoll_addfd(int fd, void (*fun)(int fd, void *arg), void *funarg, short events);
void slirpoll_delfd(int fd);

#endif
