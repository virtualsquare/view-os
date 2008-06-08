#ifdef _PCB_DEFINITIONS

#	ifdef _VIEWOS_KM
#		include <kmview.h>
#	endif


#	define PCB_INUSE 0x1 
                      /* INUSE=0: unused element ready for allocation.  
												 never = 0 for running processes pcb, 
												 INUSE=0 is a flag for pcb managed outside capture_um (capture_nested) */
#	define PCB_ALLOCATED 0x2
                        /* Dynamically allocated pcb, to be freed. */
#	define PCB_SIGNALED 0x4
                        /* awake suspended process as it has been signaled */

#	ifdef _VIEWOS_UM
#		define PCB_STARTING 0x8
                        /* the process/thread is starting */
#		define NOSC -1
#	endif

/* constants are compatible with PTRACE_SYS_VM definitions */
#	define SC_SKIP_CALL 0x5 /* SKIP_CALL */
#	define SC_SKIP_EXIT 0x2 /* SKIP_EXIT */
#	define SC_SAVEREGS 0x8
#	define SC_SUSPENDED 0x10
#	define SC_SUSPIN 0x10     /* SUSPENDED + IN  */
#	define SC_SUSPOUT 0x11    /* SUSPENDED + OUT */

#	define SC_VM_MASK 0x7 /*mask for SYS_VM */

#	define STD_BEHAVIOR SC_SKIP_EXIT  /* DO_SYSCALL SKIP_EXIT */
#	define SC_MODICALL (SC_SKIP_EXIT | SC_SAVEREGS) /* SKIP_EXIT and save regs */
#	define SC_FAKE (SC_SKIP_CALL | SC_SKIP_EXIT | SC_SAVEREGS) 
#	define SC_CALLONXIT (SC_SAVEREGS)
#	define SC_TRACEONLY ( 0 )

#	define IN 0
#	define OUT 1

#endif 

#ifdef _PCB_COMMON_FIELDS
	short flags;
#	ifdef _VIEWOS_KM
#		ifdef __NR_socketcall
			struct kmview_event_socketcall event; 
#		else
			struct kmview_event_ioctl_syscall event; 
#		endif
		struct kmview_event_ioctl_sysreturn outevent; 
		long erno;
#	endif
#	ifdef _VIEWOS_UM
		long sysscno;              /* System call number */
		unsigned long sysargs[6];
#	ifdef __NR_socketcall
		long sockaddr;
#	endif
		unsigned long erno;
#	endif
/*
 * UMPID4NESTED
 * long umpid;
 */
#endif

#ifdef _PCB_ONLY_FIELDS
	long umpid;
#	ifdef _VIEWOS_KM
	long kmpid;
	//long umpid;
#	endif
#	ifdef _VIEWOS_UM
	//unsigned short umpid;
	//long umpid;
#	endif
	int pid;                /* Process Id of this entry */
	int signum;
#	ifdef _PROC_MEM_TEST
		int memfd; /* if !has_ptrace_multi, open /proc/PID/mem */
#	endif
	struct pcb *pp;         /* Parent Process */
	short behavior;
	long retval;
#	ifdef _VIEWOS_UM
		long *saved_regs;
#	endif
#endif
