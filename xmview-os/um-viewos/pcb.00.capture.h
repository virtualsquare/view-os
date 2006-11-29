#ifdef _PCB_DEFINITIONS
#define NOSC -1
#define PCB_INUSE 0x1 /* INUSE=0: unused element ready for allocation. 
												 never = 0 for running processes pcb,
												 INUSE=0 is a flag for pcb managed outside capture_sc (capture_nested) */
#define PCB_ALLOCATED 0x2
                        /* Dynamically allocated pcb, to be freed. */
#define PCB_SIGNALED 0x4
                        /* awake suspended process as it has been signaled */
#define PCB_STARTING 0x8
                        /* the process/thread is starting */

/* constants are compatible with PTRACE_SYS_VM definitions */
#define STD_BEHAVIOR 2  /* DO_SYSCALL SKIP_EXIT */
#define SC_FAKE 3 /* SKIP_SYSCALL SKIP_EXIT */
#define SC_CALLONXIT 0  /* DO_SYSCALL DO_CALLONXIT */
#define SC_SUSPENDED 4
#define SC_SUSPIN 4     /* SUSPENDED + IN  */
#define SC_SUSPOUT 5    /* SUSPENDED + OUT */

#define IN 0
#define OUT 1

#endif 

#ifdef _PCB_COMMON_FIELDS
short flags;
long scno;              /* System call number */
unsigned long erno;
long args[8];
#endif

#ifdef _PCB_ONLY_FIELDS
unsigned short umpid;
int pid;                /* Process Id of this entry */
int signum;
#ifdef _PROC_MEM_TEST
int memfd; /* if !has_ptrace_multi, open /proc/PID/mem */
#endif
struct pcb *pp;         /* Parent Process */
short behavior;
long retval;
unsigned long arg0;
unsigned long arg1;
unsigned long arg2;

long saved_regs[VIEWOS_FRAME_SIZE];
// if regs aren't modified (because of a real syscall...), we can 
//    avoid calling PTRACE_SETREGS
char regs_modified;
#endif
