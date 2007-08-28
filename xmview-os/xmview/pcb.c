#include <config.h>
#include "pcb.h"

voidf 
#define _PCB_CONSTRUCTOR 
#include "pcb-all.h"
#undef _PCB_CONSTRUCTOR 
#define _PCB_DESTRUCTORS 
#include "pcb-all.h"
#undef _PCB_DESTRUCTORS 
dummy;

static voidfun constructors[] = {
#define _PCB_CONSTRUCTOR 
#include "pcb-all.h"
#undef _PCB_CONSTRUCTOR 
};
#define NCONSTRUCTORS sizeof(constructors)/sizeof(voidfun)

static voidfun destructors[] = {
#define _PCB_DESTRUCTOR
#include "pcb-all.h"
#undef _PCB_DESTRUCTOR 
};
#define NDESTRUCTORS sizeof(destructors)/sizeof(voidfun)

static voidfun inits[] = {
#define _PCB_INITS 
#include "pcb-all.h"
#undef _PCB_INITS 
};
#define NINITS sizeof(inits)/sizeof(voidfun)

static voidfun finis[] = {
#define _PCB_FINIS 
#include "pcb-all.h"
#undef _PCB_FINIS 
};
#define NFINIS sizeof(finis)/sizeof(voidfun)

void pcb_constructor(struct pcb *pcb,int flags,int npcbflag)
{
	register int i;
	for (i=0;i<NCONSTRUCTORS;i++)
		constructors[i](pcb,flags,npcbflag);
}

void pcb_destructor(struct pcb *pcb,int flags,int npcbflag)
{
	register int i;
	for (i=NDESTRUCTORS-1;i>=0;i--)
		destructors[i](pcb,flags,npcbflag);
}

void pcb_inits(int flags)
{
	register int i;
	for (i=0;i<NINITS;i++)
		inits[i](flags);
}

void pcb_finis(int flags)
{
	register int i;
	for (i=NFINIS-1;i>=0;i--)
		finis[i](flags);
}

