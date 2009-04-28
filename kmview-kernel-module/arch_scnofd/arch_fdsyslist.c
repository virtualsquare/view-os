#include <stdio.h>
#include "arch_unistd.h"
#include "fdsyslist.h"
#include <stdint.h>
#include <stdlib.h>

#ifdef NR_SYSCALLS
#ifndef NR_syscalls
#define NR_syscalls NR_SYSCALLS
#endif
#endif

#define SIZE32 ((NR_syscalls + 31) >> 5)
#define SIZE64 ((NR_syscalls + 63) >> 6)

uint32_t *fdsyslist32;
uint64_t *fdsyslist64;
#ifdef __NR_socketcall
uint32_t fdsocketlist32;
uint64_t fdsocketlist64;
#endif

main()
{
	int i;
	int maxsyscall=0;
	int size32,size64;
	for (i=0;i<sizeof(fdsyslist)/sizeof(int);i++) 
		if (fdsyslist[i]>maxsyscall) maxsyscall=fdsyslist[i];
	size32= (maxsyscall >> 5) + 1;
	size64= (maxsyscall >> 6) + 1;
	fdsyslist32=calloc(size32,sizeof(uint32_t));
	fdsyslist64=calloc(size64,sizeof(uint64_t));
	for (i=0;i<sizeof(fdsyslist)/sizeof(int);i++) {
		fdsyslist32[fdsyslist[i] >> 5] |= ((uint32_t)1)<<(fdsyslist[i] & 0x1f);
		fdsyslist64[fdsyslist[i] >> 6] |= ((uint64_t)1)<<(fdsyslist[i] & 0x3f);
	}
#ifdef __NR_socketcall
	for (i=2;i<19;i++) {
		if (i != 8) /*SOCKETPAIR*/ {
			fdsocketlist32 |= ((uint32_t)1)<<(i & 0x1f);
			fdsocketlist64 |= ((uint64_t)1)<<(i & 0x3f);
		}
	}
#endif
	printf("#define FDMAXSYSCALL %d\n",maxsyscall);
	printf("#define FDSYSCALL32 {");
	for (i=0;i<size32;i++) 
	printf("0x%08lx,",fdsyslist32[i]);
	printf("}\n");
	printf("#define FDSYSCALL64 {");
	for (i=0;i<size64;i++) 
		printf("0x%016llx,",fdsyslist64[i]);
	printf("}\n");
#ifdef __NR_socketcall
	printf("#define FDSOCKETCALL32 0x%08lx\n#define FDSOCKETCALL64 0x%016llx\n",
			fdsocketlist32, fdsocketlist64);
#endif
}
