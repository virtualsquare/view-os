#ifndef _PURE_LIBC_H
#define _PURE_LIBC_H

#include <config.h>

typedef long int (*sfun)(long int __sysno, ...);
extern sfun _pure_syscall;
extern sfun _pure_socketcall;
extern sfun _pure_native_syscall;
#endif
