#ifdef _UM_MMAP

#ifdef _PCB_DEFINITIONS
void um_select_addproc(),um_select_delproc();
#endif

#ifdef _PCB_COMMON_FIELDS
/* struct seldata* */
void *selset;
#endif

#ifdef _PCB_ONLY_FIELDS
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
um_select_addproc,
#endif

#ifdef _PCB_DESTRUCTOR
um_select_delproc,
#endif

#endif
