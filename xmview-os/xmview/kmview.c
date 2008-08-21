/*   This is part of km-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   kmview.c: main
 *   
 *   Copyright 2007 Renzo Davoli University of Bologna - Italy
 *   Based on umview: 2005 Renzo Davoli
 *   Modified 2005 Ludovico Gardenghi, Andrea Gasparini, Andrea Seraghiti
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
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <linux/sysctl.h>
#include <config.h>

#ifndef _VIEWOS_KM
#define _VIEWOS_KM
#endif

#include "defs.h"
#include "kmview-main.h"
#include "capture_km.h"
#include "capture_nested.h"
#include "sctab.h"
#include "services.h"
#include "um_select.h"
#include "um_services.h"
#include "mainpoll.h"
#include "gdebug.h"

#ifdef GDEBUG_ENABLED
#	define OPTSTRING "+p:o:hvxqV:u"
#else
#	define OPTSTRING "+p:hvxqV:u"
#endif

int _umview_version = 2; /* modules interface version id.
										modules can test to be compatible with
										um-viewos kernel*/
unsigned int quiet = 0;
static char *viewname;

extern int nprocs;

struct prelist {
	char *module;
	struct prelist *next;
};

/* module preload list */
static struct prelist *prehead=NULL;

/* add a module for pre-loading */
static void preadd(struct prelist **head,char *module)
{
	struct prelist *new=malloc(sizeof(struct prelist));
	assert(new);
	new->module=module;
	new->next=*head;
	*head=new;
}

#ifdef KMVIEW_RECURSIVE
/* virtual syscall for the underlying umview */
static long int_virnsyscall(long virscno,int n,long arg1,long arg2,long arg3,long arg4,long arg5,long arg6) {
	struct __sysctl_args scarg;
	long args[6]={arg1,arg2,arg3,arg4,arg5,arg6};
	scarg.name=NULL;
	scarg.nlen=virscno;
	scarg.oldval=NULL;
	scarg.oldlenp=NULL;
	scarg.newval=args;
	scarg.newlen=n;
	return native_syscall(__NR__sysctl,&scarg);
}
#endif

/* preload of modules */
static int do_preload(struct prelist *head)
{
	if (head != NULL) {
		void *handle;
		int rv=do_preload(head->next);
		handle=open_dllib(head->module);
		if (handle==NULL) {
			fprintf(stderr, "%s\n",dlerror());
			return -1;
		} else {
			set_handle_new_service(handle,0);
			return rv;
		}
		free(head);
	} else
		return 0;
}

static void do_set_viewname(char *viewname)
{
	if (viewname) {
		pcb_setviewname(get_pcb(),viewname);
		free(viewname);
	}
}

#ifdef KMVIEW_RECURSIVE
/* preload for nexted umview (it is a burst of um_add_module) */
static int do_preload_recursive(struct prelist *head)
{
	if (head != NULL) {
		do_preload_recursive(head->next);
		int_virnsyscall(__NR_UM_SERVICE,3,ADD_SERVICE,0,(long)head->module,0,0,0);
		free(head);
		return 0;
	} else
		return 0;
}

static void do_set_viewname_recursive(char *viewname)
{
	if (viewname) {
		int_virnsyscall(__NR_UM_SERVICE,2,UMVIEW_SETVIEWNAME,(long)viewname,0,0,0,0);
	}
}
#endif

static void version(int verbose)
{
	fprintf(stderr, "%s %s\n", KMVIEW_NAME, KMVIEW_VERSION);

	if (verbose)
		fprintf(stderr, "%s\n", KMVIEW_DESC);

	fprintf(stderr, "Copyright (C) %s\n", KMVIEW_COPYRIGHT);
	
	if (verbose)
		fprintf(stderr, "Development team:\n%s\n", KMVIEW_TEAM);

	fprintf(stderr, "%s\n\n", KMVIEW_URL);
	return;
}

static void usage(char *s)
{
	version(0);
	
	fprintf(stderr, "Usage: %s [OPTION] ... command [args]\n"
			"  -h, --help                print this help message\n"
			"  -v, --version             show version information\n"
			"  -q, --quiet               suppress some additional output\n"
			"  -V name, --viewname name  set the view name\n"
			"  -p file, --preload file   load plugin named `file' (must be a .so)\n"
#ifdef GDEBUG_ENABLED
			"  -o file, --output file    send debug messages to file instead of stderr\n"
#endif
			"  -x, --nonesting           do not permit module nesting\n"
			"  -u, --userrecursion       recursive invocation on the existing hypervisor\n",
			s);
	exit(0);
}

static struct option long_options[] = {
	{"preload",1,0,'p'},
#ifdef GDEBUG_ENABLED
	{"output",1,0,'o'},
#endif
	{"version",0,0,'v'},
	{"quiet",0,0,'q'},
	{"viewname",1,0,'V'},
	{"help",0,0,'h'},
	{"nonesting",0,0,'x'},
	{"userrecursion",0,0,'u'},
	{0,0,0,0}
};

/* pure_libc loading (by reloading the entire kmview) */
static void load_it_again(int argc,char *argv[])
{
	int nesting=1;
	while (1) {
		int c;
		int option_index = 0;
		/* some options must be parsed before reloading */
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

		if (c == -1) break;
		switch (c) {
			case 'h':
				usage(basename(argv[0]));
				break;
			case 'v':
				version(1);
				exit(0);
				break;
			case 'x': /* do not use pure_libc */
				nesting=0;
				break;
		}
	}
	if (nesting) {
		char *path;
		void *handle;
		/* does pure_libc exist ? */
		if ((handle=dlopen("libpurelibc.so",RTLD_LAZY))!=NULL) {
			dlclose(handle);
			/* get the executable from /proc */
			asprintf(&path,"/proc/%d/exe",getpid());
			/* preload the pure_libc library */
			setenv("LD_PRELOAD","libpurelibc.so",1);
			/* reload the executable with a leading - */
			argv[0]="--kmview";
			execv(path,argv);
			/* useless cleanup */
			free(path);
		}
	}
}

#ifdef KMVIEW_RECURSIVE

/* recursive kmview invocation (umview started inside a umview machine) */
static void kmview_recursive(int argc,char *argv[])
{
	if (argc < 2)
	{
		usage(argv[0]);
		exit(1);
	}

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'q':
				quiet = 1;
				break;
			case 'v':
				version(1);
				exit(0);
				break;
			case 'V':
				viewname=strdup(optarg);
				break;
			case 'p': 
				preadd(&prehead,optarg);
				break;
		}
	}
	if (!quiet)
		fprintf(stderr,"UMView: nested invocation\n\n");
	do_preload_recursive(prehead);
	do_set_viewname_recursive(viewname);
	/* exec the process */
	execvp(*(argv+optind),argv+optind);
	exit(-1);
}

static int test_recursion(int argc,char *argv[])
{
	int userrecursion=0;
	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, OPTSTRING, NULL, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'u':
				userrecursion = 1;
				break;
		}
	}
	return userrecursion;
}

#endif

static void root_process_init()
{
	capture_nested_init();
	setenv("_INSIDE_UMVIEW_MODULE","",1);
	do_preload(prehead);
	do_set_viewname(viewname);
}

#define PROGNAME "kmview"
#include<errno.h>
/* KMVIEW MAIN PROGRAM */
int main(int argc,char *argv[])
{
	if (argc < 2) /* NO ARGS */
	{
		usage(PROGNAME);
		exit(1);
	}

	/* try to set the priority to -11 provided umview has been installed
	 * setuid. it is effectiveless elsewhere */
	r_setpriority(PRIO_PROCESS,0,-11);
	/* if it was setuid, return back to the user status immediately,
	 * for safety! */
	r_setuid(getuid());
	/* if this is a nested invocation of umview, notify the umview monitor
	 * and execute the process, 
	 * try the nested invocation notifying virtual syscall, 
	 * if it succeeded it is actually a nested invocation,
	 * otherwise nobody is notified and the call fails*/
#if 0
#define KMVIEW_RECURSIVE
	if (test_recursion(argc,argv)) {
		if (int_virnsyscall(__NR_UM_SERVICE,1,RECURSIVE_UMVIEW,0,0,0,0,0) >= 0)
			kmview_recursive(argc,argv);	/* do not return!*/
	}
#endif
	/* umview loads itself twice if there is pure_libc, to trace module 
	 * generated syscalls, this condition manages the first call */
	if (strcmp(argv[0],"--kmview")!=0)
		load_it_again(argc,argv);	/* do not return (when purelibc and not -x)!*/

	/* does this kernel provide pselect? */
	/*has_pselect=has_pselect_test();*/
	optind=1;
	/* set up the scdtab */
	scdtab_init();
	/* test the ptrace support */
	/* option management */
	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'h': /* help */
				usage(PROGNAME);
				break;
			case 'v': /* version */
				version(1);
				exit(0);
				break;
			case 'V':
				viewname=strdup(optarg);
				break;
			/* XXX todo preload */
			case 'p': /* module preload, here the module requests are just added to
			             a data structure */
				preadd(&prehead,optarg);
				break;
			case 'q':
				quiet = 1;
				break;
#ifdef GDEBUG_ENABLED
			case 'o': /* debugging output file redirection */ { 
						if (optarg==NULL){
							fprintf(stderr, "%s: must specify an argument after -o\n",argv[0]);
							break;
						}
						gdebug_set_ofile(optarg);
					 }
					 break;
#endif
		}
	}
	
	if (!quiet) {
		fprintf(stderr, "Kmview: %s\nver: %s\n\n",KMVIEW_DESC,PACKAGE_VERSION);
	}

	sigset_t unblockchild;
	sigprocmask(SIG_BLOCK,NULL,&unblockchild);
	pcb_inits(0);
	if (capture_main(argv+optind,root_process_init) < 0) {
		fprint2("Kmview: kernel module not loaded\n");
		exit(1);
	}
	mp_add(kmviewfd,POLLIN,tracehand,NULL,1);
	GDEBUG(3,"ENTERING %d ",kmviewfd);
	do {
		mp_ppoll(&unblockchild);
	} while (nprocs>0);
	pcb_finis(0);
	return first_child_exit_status;
}

