#ifndef KMVIEW_ARCH_X86_64_H
#define KMVIEW_ARCH_X86_64_H
#include <linux/utrace.h>

#ifndef BITS_PER_LONG
#error "BITS_PER_LONG undefined"
#endif

#define PATHSYSCALL { 0x00200054,0x00000000,0x57fc1000,0x00000000,0x00000230,0xb0000000,0x0000006d,0x00000800,0x01003ffe,0x00000000,0x00000000,0x00000000}
#define PATH0SYSCALL { 0x00200054,0x00000000,0x56b81000,0x00000000,0x00000230,0xb0000000,0x0000006d,0x00000800,0x00000000,0x00000000,0x00000000,0x00000000}
#define PATH1SYSCALL { 0x00000000,0x00000000,0x01440000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x010038fe,0x00000000,0x00000000,0x00000000}
#define PATH2SYSCALL { 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000400,0x00000000,0x00000000,0x00000000}
#define PATH3SYSCALL { 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000300,0x00000000,0x00000000,0x00000000}
#define ATSYSCALL { 0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x01003ffe,0x00000000,0x00000000,0x00000000}
#define SELECTPOLLSYSCALL { 0x00800080,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x0000c000,0x00000000,0x00000000,0x00000000}
#define FDSYSCALL { 0x001f012b,0x00dffc00,0x28026f00,0x00000000,0x00000400,0x48000000,0x22000092,0x00000000,0x00003070,0x00000001,0x00000000,0x00000000}

#define MAXERR 4096
#define arch_scno(X) ((X)->orig_ax)
#ifdef __KMVIEW_MAIN
int _kmview_permute[]={14,13,12,7,9,8};
#else
extern int _kmview_permute[];
#endif

/*static inline inline permute(int x) {
	switch (x) {
		case 0: return 14;
		case 1: return 13;
		case 2: return 12;
		case 3: return 7;
		case 4: return 9;
		case 5: return 8;
	}
	return 0;
}*/

//#define arch_n(X,N) (*(((unsigned long *)(X))+(N))
#define arch_n(X,N) (*(((unsigned long *)(X))+(_kmview_permute[(N)])))

#define arch_sp(X) ((X)->sp)
#define arch_pc(X) ((X)->ip)
#define arch_get_rv(X) ({ long ax; \
		    ax = (long) ((X)->ax);\
		    (ax<0 && -ax < MAXERR)? -1 : ax; })
#define arch_get_errno(X) ({ int ax; \
		    ax = (long) ((X)->ax);\
		    (ax<0 && -ax < MAXERR)? -ax : 0; })
#define arch_put_rv_errno(X,RV,ERRNO) ({if ((ERRNO) != 0) {\
		if ((ERRNO) < 0) (ERRNO)=-ERRNO;\
		(X)->ax=-(ERRNO); } else\
		(X)->ax=(RV); })

#endif
