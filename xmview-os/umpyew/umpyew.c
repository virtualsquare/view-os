/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   example of um-ViewOS module:
 *   remap of /unreal onto the real FS
 *   /unreal/XXXX is mapped to XXXX in th real FS
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2, as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 *   $Id$
 *
 */   
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <string.h>
#include <utime.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <config.h>
#include "module.h"
#include "libummod.h"

#include "gdebug.h"

// int read(), write(), close();

struct pService
{
	PyObject *ctl;
	PyObject *checkfun;
	PyObject *syscall;
	PyObject *socket;
};

static struct service s;
static struct pService ps;

#if 0
static struct timestamp t1;
static struct timestamp t2;

static epoch_t unrealpath(int type,void *arg)
{
	/* This is an example that shows how to pick up extra info in the
	 * calling process. */
/*	printf("test umph info pid=%d, scno=%d, arg[0]=%d, argv[1]=%d\n",
			um_mod_getpid(),um_mod_getsyscallno(),
			um_mod_getargs()[0],um_mod_getargs()[1]); */
/* NB: DEVELOPMENT PHASE !! */
	if (type== CHECKPATH) {
		char *path=arg;
		epoch_t e=0;
		if(strncmp(path,"/unreal",7) == 0) {
			if ((e=tst_matchingepoch(&t2)) == 0)
				e=tst_matchingepoch(&t1);
			//fprint2("MATCH e=%lld\n",e);
		}
		return e;
	}
	else
		return 0;
}

static long addproc(int id, int max)
{
	fprintf(stderr, "add proc %d %d\n", id, max);
	GDEBUG(3, "new process id %d  pid %d   max %d",id,um_mod_getpid(),max);
	return 0;
}

static long delproc(int id)
{
	fprintf(stderr, "del proc %d\n", id);
	GDEBUG(3, "terminated process id %d  pid %d",id,um_mod_getpid());
	return 0;
}

static long addmodule(int code)
{
	fprintf(stderr, "add module 0x%02x\n", code);
	GDEBUG(3, "new module loaded. code 0x%02x", code);
	return 0;
}

static long delmodule(int code)
{
	fprintf(stderr, "del module 0x%02x\n", code);
	GDEBUG(3, "module 0x%02x removed", code);
	return 0;
}


static long ctl(int type, va_list ap)
{
	int id, ppid, max, code;

	switch(type)
	{
		case MC_PROC | MC_ADD:
			id = va_arg(ap, int);
			ppid = va_arg(ap, int);
			max = va_arg(ap, int);
			return addproc(id, max);
			
		case MC_PROC | MC_REM:
			id = va_arg(ap, int);
			return delproc(id);

		case MC_MODULE | MC_ADD:
			code = va_arg(ap, int);
			return addmodule(code);

		case MC_MODULE | MC_REM:
			code = va_arg(ap, int);
			return delmodule(code);
		
		default:
			return -1;
	}
}

static char *unwrap(char *path)
{
	char *s;
	s=&(path[7]);
	if (*s == 0) s = "/";
	return (s);
}

static long unreal_open(char *pathname, int flags, mode_t mode)
{
	/* send the file name to every module except myself (just for testing) */
	service_userctl(42, s.code, MC_ALLSERVICES, pathname);
	/* send the file name to module 0xfc (i.e. testmodule) */
//	service_userctl(42, s.code, 0xfc, pathname);

	return open(unwrap(pathname),flags,mode);
}

static long unreal_statfs64(char *pathname, struct statfs64 *buf)
{
	return statfs64(unwrap(pathname),buf);
}

static long unreal_stat64(char *pathname, struct stat64 *buf)
{
	return stat64(unwrap(pathname),buf);
}

static long unreal_lstat64(char *pathname, struct stat64 *buf)
{
	return lstat64(unwrap(pathname),buf);
}

static long unreal_readlink(char *path, char *buf, size_t bufsiz)
{
	return readlink(unwrap(path),buf,bufsiz);
}

static long unreal_access(char *path, int mode)
{
	return access(unwrap(path),mode);
}

static long unreal_mkdir(char *path, int mode)
{
	return mkdir(unwrap(path),mode);
}

static long unreal_rmdir(char *path)
{
	return rmdir(unwrap(path));
}

static long unreal_chmod(char *path, int mode)
{
	return chmod(unwrap(path),mode);
}

static long unreal_chown(char *path, uid_t owner, gid_t group)
{
	return chown(unwrap(path),owner,group);
}

static long unreal_lchown(char *path, uid_t owner, gid_t group)
{
	return lchown(unwrap(path),owner,group);
}

static long unreal_unlink(char *path)
{
	return unlink(unwrap(path));
}

static long unreal_link(char *oldpath, char *newpath)
{
	return link(unwrap(oldpath),unwrap(newpath));
}

static long unreal_symlink(char *oldpath, char *newpath)
{
	return symlink(oldpath,unwrap(newpath));
}

static long unreal_utime(char *filename, struct utimbuf *buf)
{
	return utime(unwrap(filename),buf);
}

static long unreal_utimes(char *filename, struct timeval tv[2])
{
	return utimes(unwrap(filename),tv);
}

static ssize_t unreal_pread(int fd, void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pread(fd,buf,count,off);
}

static ssize_t unreal_pwrite(int fd, const void *buf, size_t count, long long offset)
{
	off_t off=offset;
	return pwrite(fd,buf,count,off);
}

static long unreal_lseek(int fildes, int offset, int whence)
{
	return (int) lseek64(fildes, (off_t) offset, whence);
}

#endif


static void
__attribute__ ((constructor))
init (void)
{
	const char *name = "umpyew-testmodule";

	PyObject *pName, *pModule;

	GMESSAGE("umpyew init");
	s.name="Prototypal Python bindings for *MView";
	s.code=0x07;
	s.syscall=(sysfun *)calloc(scmap_scmapsize,sizeof(sysfun));
	s.socket=(sysfun *)calloc(scmap_sockmapsize,sizeof(sysfun));

	Py_Initialize();
	pName = PyString_FromString(name);

	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (!pModule)
	{
		GERROR("Error loading Python module %s.", name);
		PyErr_Print();
		return;
	}

	if ((ps.ctl = PyObject_GetAttrString(pModule, "modCtl")) && PyCallable_Check(ps.ctl))
		s.ctl = ctl;
	else
	{
		GERROR("function modCtl not defined in module %s", name);
		Py_XDECREF(ps.ctl);
		return;
	}

	if ((ps.checkfun = PyObject_GetAttrString(pModule, "modCheckFun")) && PyCallable_Check(ps.checkfun))
		s.checkfun = checkfun;
	else
	{
		GERROR("function modCheckFun not defined in module %s", name);
		Py_DECREF(ps.ctl);
		Py_XDECREF(ps.checkfun);
		return;
	}
	
	add_service(&s);
	
#if 0	
	MCH_ZERO(&(s.ctlhs));
	MCH_SET(MC_PROC, &(s.ctlhs));
	MCH_SET(MC_MODULE, &(s.ctlhs));

	SERVICESYSCALL(s, open, unreal_open);
	SERVICESYSCALL(s, read, read);
	SERVICESYSCALL(s, write, write);
	SERVICESYSCALL(s, close, close);
#if 0
	SERVICESYSCALL(s, stat, unreal_stat64);
	SERVICESYSCALL(s, lstat, unreal_lstat64);
	SERVICESYSCALL(s, fstat, fstat64);
#endif
#if !defined(__x86_64__)
	SERVICESYSCALL(s, stat64, unreal_stat64);
	SERVICESYSCALL(s, lstat64, unreal_lstat64);
	SERVICESYSCALL(s, fstat64, fstat64);
#else
	SERVICESYSCALL(s, stat, unreal_stat64);
	SERVICESYSCALL(s, lstat, unreal_lstat64);
	SERVICESYSCALL(s, fstat, fstat64);
#endif
	SERVICESYSCALL(s, readlink, unreal_readlink);
#if 0 
	SERVICESYSCALL(s, getdents, getdents64);
#endif
	SERVICESYSCALL(s, getdents64, getdents64);
	SERVICESYSCALL(s, access, unreal_access);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, fcntl, fcntl32);
	SERVICESYSCALL(s, fcntl64, fcntl64);
	SERVICESYSCALL(s, _llseek, _llseek);
#else
	SERVICESYSCALL(s, fcntl, fcntl);
#endif
	SERVICESYSCALL(s, lseek,  unreal_lseek);
	SERVICESYSCALL(s, mkdir, unreal_mkdir);
	SERVICESYSCALL(s, rmdir, unreal_rmdir);
	SERVICESYSCALL(s, chown, unreal_chown);
	SERVICESYSCALL(s, lchown, unreal_lchown);
	SERVICESYSCALL(s, fchown, fchown);
	SERVICESYSCALL(s, chmod, unreal_chmod);
	SERVICESYSCALL(s, fchmod, fchmod);
	SERVICESYSCALL(s, unlink, unreal_unlink);
	SERVICESYSCALL(s, fsync, fsync);
	SERVICESYSCALL(s, fdatasync, fdatasync);
	SERVICESYSCALL(s, _newselect, select);
	SERVICESYSCALL(s, link, unreal_link);
	SERVICESYSCALL(s, symlink, unreal_symlink);
	SERVICESYSCALL(s, pread64, unreal_pread);
	SERVICESYSCALL(s, pwrite64, unreal_pwrite);
	SERVICESYSCALL(s, utime, unreal_utime);
	SERVICESYSCALL(s, utimes, unreal_utimes);
#if !defined(__x86_64__)
	SERVICESYSCALL(s, statfs64, unreal_statfs64);
	SERVICESYSCALL(s, fstatfs64, fstatfs64);
#else
	SERVICESYSCALL(s, statfs, unreal_statfs64);
	SERVICESYSCALL(s, fstatfs, fstatfs64);
#endif
#endif

}

static void
__attribute__ ((destructor))
fini (void)
{
	GBACKTRACE(5,20);
	free(s.syscall);
	free(s.socket);

	
	Py_Finalize();
	GMESSAGE("unreal fini");
}
