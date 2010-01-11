#include <stdio.h>
#include "arch_unistd.h"
#include "pathsyslist.h"
#include "fdsyslist.h"
#include <stdint.h>
#include <stdlib.h>
#include "../kmview.h"

int pathsyscall[INT_PER_MAXSYSCALL];
int path0syscall[INT_PER_MAXSYSCALL];
int path1syscall[INT_PER_MAXSYSCALL];
int path2syscall[INT_PER_MAXSYSCALL];
int path3syscall[INT_PER_MAXSYSCALL];
int atsyscall[INT_PER_MAXSYSCALL];
int selectpollsyscall[INT_PER_MAXSYSCALL];
int fdsyscall[INT_PER_MAXSYSCALL];
int fdsocketlist;
main()
{
	int i,c;
	for (i=0;i<sizeof(path0syslist)/sizeof(int);i++) {
		scbitmap_set(path0syscall,path0syslist[i]);
		scbitmap_set(pathsyscall,path0syslist[i]);
	}
	for (i=0;i<sizeof(path1syslist)/sizeof(int);i++) {
		scbitmap_set(path1syscall,path1syslist[i]);
		scbitmap_set(pathsyscall,path1syslist[i]);
	}
	for (i=0;i<sizeof(path2syslist)/sizeof(int);i++) {
		scbitmap_set(path2syscall,path2syslist[i]);
		scbitmap_set(pathsyscall,path2syslist[i]);
	}
	for (i=0;i<sizeof(path3syslist)/sizeof(int);i++) {
		scbitmap_set(path3syscall,path3syslist[i]);
		scbitmap_set(pathsyscall,path3syslist[i]);
	}
	for (i=0;i<sizeof(atsyslist)/sizeof(int);i++) 
		scbitmap_set(atsyscall,atsyslist[i]);
	for (i=0;i<sizeof(selectpollsyslist)/sizeof(int);i++) 
		scbitmap_set(selectpollsyscall,selectpollsyslist[i]);
	for (i=0;i<sizeof(fdsyslist)/sizeof(int);i++) 
		scbitmap_set(fdsyscall,fdsyslist[i]);
	printf("#define PATHSYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,pathsyscall[i]);
	printf("}\n");
	printf("#define PATH0SYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,path0syscall[i]);
	printf("}\n");
	printf("#define PATH1SYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,path1syscall[i]);
	printf("}\n");
	printf("#define PATH2SYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,path2syscall[i]);
	printf("}\n");
	printf("#define PATH3SYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,path3syscall[i]);
	printf("}\n");
	printf("#define ATSYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,atsyscall[i]);
	printf("}\n");
	printf("#define SELECTPOLLSYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,selectpollsyscall[i]);
	printf("}\n");
	printf("#define FDSYSCALL {");
	for (i=0,c=' ';i<INT_PER_MAXSYSCALL;i++,c=',') 
		printf("%c0x%08lx",c,fdsyscall[i]);
	printf("}\n");
}
