#ifdef _UM_PTRACE

#ifdef _PCB_DEFINITIONS
#define PTRACE_STATUS_TERMINATED 1
#define PTRACE_STATUS_SYSCALL 2
#define PTRACE_STATUS_SINGLESTEP 4
#define PTRACE_STATUS_SYSOUT 0x100

#define PT_TRACED(pc) ((pc)->ptrace_pp)

struct pcblist;
void um_ptrace_addproc(),um_ptrace_delproc();
#endif

#ifdef _PCB_COMMON_FIELDS
struct pcb *ptrace_pp;
struct pcblist *ptrace_notify_head;
long ptrace_ntraced;
long ptrace_request;
long ptrace_status;
long ptrace_options;
pid_t ptrace_waitpid;
int ptrace_nchildren;
int ptrace_nterminated;
#endif

#ifdef _PCB_ONLY_FIELDS
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
um_ptrace_addproc,
#endif

#ifdef _PCB_DESTRUCTOR
um_ptrace_delproc,
#endif

#endif
