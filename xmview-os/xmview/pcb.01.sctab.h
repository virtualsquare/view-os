#ifdef _PCB_DEFINITIONS
#define MAX_SOCKET_ARGS 6

struct supgroups {
	int count;
	size_t size;
	gid_t list[0];
};
struct supgroups *supgrp_create(size_t size);
struct supgroups *supgrp_get(struct supgroups *supgrp);
void supgrp_put(struct supgroups *supgrp);

void pcb_plus(),pcb_minus();
/* STATUS DEFINITIONS */
#define READY 0

#endif

#ifdef _PCB_COMMON_FIELDS
void *path;
struct stat64 pathstat;
struct ht_elem *hte;
void *mod_private_data;
struct timestamp tst;
epoch_t nestepoch;
/* path for tmp files that must be deleted over the next syscall */
/* see execve mgmt */
void *tmpfile2unlink_n_free;
uid_t ruid,euid,suid,fsuid;
gid_t rgid,egid,sgid,fsgid;
struct supgroups *grouplist;
uint16_t private_scno;
uint8_t needs_path_rewrite;
uint32_t tags;
#endif

#ifdef _PCB_ONLY_FIELDS
/* keep track of file system informations - look at clone 2
 *    * (CLONE_FS) */
struct pcb_fs *fdfs;
#endif

#ifdef _NPCB_ONLY_FIELDS
#endif

#ifdef _PCB_CONSTRUCTOR
pcb_plus,
#endif
#ifdef _PCB_DESTRUCTOR
pcb_minus,
#endif
