#ifndef _MAINPOLL_H
#define _MAINPOLL_H
#include <poll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "defs.h"

int hasppolltest();

void bq_add(void (*fun)(struct pcb *), struct pcb *pc);
void bq_signal(struct pcb *pc);
int bq_pidwake(long pid,int signum);

void bq_ppolltry();
void mp_add(int fd, short events, void (*fun)(void *), void *arg);
void mp_del(int fd, void *arg);

int mp_poll();
int mp_ppoll( const sigset_t *sigmask);

void mainpoll_init(int useppoll);
#endif
