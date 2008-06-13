#ifndef _PCB_H
#define _PCB_H
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include "treepoch.h"

#if defined(__powerpc__) //setregs/getresg for ppc
#define FRAME_SIZE 13
#elif defined(__x86_64__) // asm-x86_64 define it as 168 [offset in bytes] ! 
#define VIEWOS_FRAME_SIZE 28
#endif

#ifndef VIEWOS_FRAME_SIZE
#define VIEWOS_FRAME_SIZE FRAME_SIZE
#endif 

typedef void (*voidfun)();
typedef void voidf();

#define _PCB_DEFINITIONS
#include "pcb-all.h"
#undef _PCB_DEFINITIONS

struct pcb {
#define _PCB_COMMON_FIELDS 
#include "pcb-all.h"
#undef _PCB_COMMON_FIELDS 
#define _PCB_ONLY_FIELDS 
#include "pcb-all.h"
#undef _PCB_ONLY_FIELDS 
};
  
struct npcb {
#define _PCB_COMMON_FIELDS 
#include "pcb-all.h"
#undef _PCB_COMMON_FIELDS 
#define _NPCB_ONLY_FIELDS 
#include "pcb-all.h"
#undef _NPCB_ONLY_FIELDS 
};

void pcb_constructor(struct pcb *pcb,int flags,int npcbflag);
void pcb_destructor(struct pcb *pcb,int flags,int npcbflag);
void pcb_inits(int flags);
void pcb_finis(int flags);

#endif
