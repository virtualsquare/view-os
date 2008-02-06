#ifndef _PURELIBC_H
#define _PURELIBC_H

#include <config.h>

typedef long int (*sfun)(long int __sysno, ...);
extern sfun _pure_syscall;
extern sfun _pure_socketcall;
extern sfun _pure_native_syscall;
#endif
