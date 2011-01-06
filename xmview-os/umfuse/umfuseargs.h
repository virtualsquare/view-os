#ifndef UMFUSEARGS_H
#define UMFUSEARGS_H
struct fuse_context;
int fuseargs(char* filesystemtype,char *source, char *mountpoint, char *opts, char ***pargv,struct fuse_context *fc,unsigned long *pflags,char ***pexceptions);
void fusefreearg(int argc,char *argv[]);
#endif
