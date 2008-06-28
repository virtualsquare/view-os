#ifdef _UM_MMAP

#ifdef _PCB_DEFINITIONS
struct pcb_file;
void umproc_addproc(),umproc_delproc();
#endif

#ifdef _PCB_COMMON_FIELDS
#endif

#ifdef _PCB_ONLY_FIELDS
/* file descriptors of this process */
struct pcb_file *fds;
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
umproc_addproc,
#endif

#ifdef _PCB_DESTRUCTOR
umproc_delproc,
#endif

#endif
