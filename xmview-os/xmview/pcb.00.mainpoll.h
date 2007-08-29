#ifdef _PCB_DEFINITIONS

/* STATUS DEFINITIONS */
void mainpoll_addproc(),mainpoll_delproc(),mainpoll_init();

#define READY 0
#define BLOCKED 1
#define WAKE_ME_UP 2
#define TERMINATED 3

#define bq_block(pc) ((pc)->pollstatus=BLOCKED)
#define bq_unblock(pc) ((pc)->pollstatus=READY)

#endif

#ifdef _PCB_COMMON_FIELDS
int pollstatus;
#endif

#ifdef _PCB_ONLY_FIELDS
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
mainpoll_addproc,
#endif
#ifdef _PCB_DESTRUCTOR
mainpoll_delproc,
#endif
#ifdef _PCB_INITS
mainpoll_init,
#endif
