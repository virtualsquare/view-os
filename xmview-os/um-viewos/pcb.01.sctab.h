#ifdef _PCB_DEFINITIONS
#define MAX_SOCKET_ARGS 6

void pcb_plus(),pcb_minus();
/* STATUS DEFINITIONS */
#define READY 0

#endif

#ifdef _PCB_COMMON_FIELDS
void *path;
struct stat64 pathstat;
struct timestamp tst;
epoch_t nestepoch;
/* path for tmp files that must be deleted over the next syscall */
/* see execve mgmt */
void *tmpfile2unlink_n_free;
#endif

#ifdef _PCB_ONLY_FIELDS
/* keep track of file system informations - look at clone 2
 *    * (CLONE_FS) */
struct pcb_fs *fdfs;
/* PTRACE_MULTI for Sockets */
/* This management must be unified with nested! */
long sockregs[MAX_SOCKET_ARGS];
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
pcb_plus,
#endif
#ifdef _PCB_DESTRUCTOR
pcb_minus,
#endif
