#ifndef KMVIEW_ARCH_I386_H
#define KMVIEW_ARCH_I386_H
#include <linux/utrace.h>

#define FDMAXSYSCALL 307
#define FDSYSCALL32 {0x10080058,0x00c00000,0xe2000000,0x00401010,0x0016b020,0x00300000,0x30008024,0x04002492,0x00012000,0x000c1c00,}
#define FDSYSCALL64 {0x00c0000010080058,0x00401010e2000000,0x003000000016b020,0x0400249230008024,0x000c1c0000012000,}
#define FDSOCKETCALL32 0x0003fefc
#define FDSOCKETCALL64 0x000000000003fefc

#define MAXERR 4096
#define arch_scno(X) ((X)->orig_ax)
#define arch_n(X,N) (*(((long *)(X))+(N)))
#define arch_sp(X) ((X)->sp)
#define arch_pc(X) ((X)->ip)
#define arch_get_rv(X) ({ int ax; \
		    ax = (X)->ax;\
		    (ax<0 && -ax < MAXERR)? -1 : ax; })
#define arch_get_errno(X) ({ int ax; \
		    ax = (X)->ax;\
		    (ax<0 && -ax < MAXERR)? -ax : 0; })
#define arch_put_rv_errno(X,RV,ERRNO) ({if ((ERRNO) != 0) {\
		if ((ERRNO) < 0) (ERRNO)=-ERRNO;\
		(X)->ax=-(ERRNO); } else\
		(X)->ax=(RV); })

#ifndef BITS_PER_LONG
#error "BITS_PER_LONG undefined"
#endif

extern unsigned long fdsyslist[];
#ifdef __NR_socketcall
extern unsigned long fdsocketlist;
#endif
#if BITS_PER_LONG==32
	static inline int isfdsys(unsigned long x) {
		if (x<0 || x>FDMAXSYSCALL)
			return 0;
		else
			return (fdsyslist[x >> 5] & (1 << (x & 0x1f)));
	}
#endif
#if BITS_PER_LONG==64
	static inline int isfdsys(unsigned long x) {
		if (x<0 || x>FDMAXSYSCALL)
			return 0;
		else
			return (fdsyslist[x >> 6] & (1 << (x & 0x3f)));
	}
#endif
#ifdef __NR_socketcall
	static inline int isfdsocket(unsigned long x) {
		if (x<0 || x>17) 
			return 0;
		else
			return (fdsocketlist & (1 << x));
	}
#endif

#endif
