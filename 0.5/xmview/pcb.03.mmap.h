#ifdef _UM_MMAP

#ifdef _PCB_DEFINITIONS
struct pcb_mmap_entry;
void um_mmap_addproc(),um_mmap_delproc();
#endif

#ifdef _PCB_COMMON_FIELDS
#endif

#ifdef _PCB_ONLY_FIELDS
struct pcb_mmap_entry *um_mmap;
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
um_mmap_addproc,
#endif

#ifdef _PCB_DESTRUCTOR
um_mmap_delproc,
#endif

#endif
