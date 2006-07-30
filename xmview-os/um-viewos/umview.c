/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umview.c: main
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
 *   Modified 2005 Ludovico Gardenghi, Andrea Gasparini, Andrea Seraghiti
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */   
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <linux/sysctl.h>
#include "defs.h"
#include "umview.h"
#include "capture_sc.h"
#include "sctab.h"
#include "services.h"
#include "um_select.h"
#include "um_services.h"
#include "ptrace_multi_test.h"
#include "gdebug.h"

int _umview_version = 1; /* modules interface version id.
										modules can test to be compatible with
										um-viewos kernel*/
unsigned int has_ptrace_multi;
unsigned int ptrace_vm_mask;
unsigned int ptrace_viewos_mask;

unsigned int want_ptrace_multi, want_ptrace_vm, want_ptrace_viewos;

extern int nprocs;

struct prelist {
	char *module;
	struct prelist *next;
};
static struct prelist *prehead=NULL;

static void preadd(struct prelist **head,char *module)
{
	struct prelist *new=malloc(sizeof(struct prelist));
	assert(new);
	new->module=module;
	new->next=*head;
	*head=new;
}

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

static void version(int verbose)
{
	fprintf(stderr, "%s %s\n", UMVIEW_NAME, UMVIEW_VERSION);

	if (verbose)
		fprintf(stderr, "%s\n", UMVIEW_DESC);

	fprintf(stderr, "Copyright (C) %s\n", UMVIEW_COPYRIGHT);
	
	if (verbose)
		fprintf(stderr, "Development team:\n%s\n", UMVIEW_TEAM);

	fprintf(stderr, "%s\n\n", UMVIEW_URL);
	return;
}

static void usage(char *s)
{
	version(0);
	
	fprintf(stderr, "Usage: %s [OPTION] ... command [args]\n"
			"  -h, --help                print this help message\n"
			"  -v, --version             show version information\n"
			"  -p file, --preload file   load plugin named `file' (must be a .so)\n"
			"  -o file, --output file    send debug messages to file instead of stderr\n"
			"  -x, --nonesting           do not permit module nesting\n"
			"  -n, --nokernelpatch       avoid using kernel patches\n"
			"  --nokmulti                avoid using PTRACE_MULTI\n"
			"  --nokvm                   avoid using PTRACE_SYSVM\n"
			"  --nokviewos               avoid using PTRACE_VIEWOS\n\n",
			s);
	exit(0);
}

static struct option long_options[] = {
	{"preload",1,0,'p'},
	{"output",1,0,'o'},
	{"help",0,0,'h'},
	{"nonesting",0,0,'x'},
	{"nokernelpatch",0,0,'n'},
	{"nokmulti",0,0,0x100},
	{"nokvm",0,0,0x101},
	{"nokviewos",0,0,0x102},
	{0,0,0,0}
};

static void load_it_again(int argc,char *argv[])
{
	int nesting=1;
	while (1) {
		int c;
		int option_index = 0;
		c=getopt_long(argc,argv,"+p:o:hvnx",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				version(1);
				exit(0);
				break;
			case 'x':
				nesting=0;
				break;
		}
	}
	if (nesting) {
		char *path;
		void *handle;
		if ((handle=dlopen("libpure_libc.so",RTLD_LAZY))!=NULL) {
			dlclose(handle);
			asprintf(&path,"/proc/%d/exe",getpid());
			setenv("LD_PRELOAD","libpure_libc.so",1);
			argv[0]="-umview";
			execv(path,argv);
			free(path);
		}
	}
}

static void umview_recursive(int argc,char *argv[])
{
	fprintf(stderr,"UMView: nested invocation\n\n");
	while (1) {
		int c;
		int option_index = 0;
		c=getopt_long(argc,argv,"+p:o:hvnx",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				version(1);
				exit(0);
				break;
			case 'p': 
				preadd(&prehead,optarg);
				break;
		}
	}
	do_preload_recursive(prehead);
	execvp(*(argv+optind),argv+optind);
	exit(-1);
}

static int has_pselect_test()
{
#ifdef _USE_PSELECT
	static struct timespec to={0,0};
	return (r_pselect6(0,NULL,NULL,NULL,&to,NULL)<0)?0:1;
#else
	return 0;
#endif
}

int main(int argc,char *argv[])
{
	fd_set wset[3];
	int has_pselect;
	
	r_setpriority(PRIO_PROCESS,0,-11);
	r_setuid(getuid());
	if (int_virnsyscall(__NR_UM_SERVICE,1,RECURSIVE_UMVIEW,0,0,0,0,0) >= 0)
		umview_recursive(argc,argv);	/* do not return!*/
	if (strcmp(argv[0],"-umview")!=0)
		load_it_again(argc,argv);	/* do not return!*/
	has_pselect=has_pselect_test();
	optind=0;
	argv[0]="umview";
	scdtab_init();
	has_ptrace_multi=test_ptracemulti(&ptrace_vm_mask,&ptrace_viewos_mask);
	want_ptrace_multi = has_ptrace_multi;
	want_ptrace_vm = ptrace_vm_mask;
	want_ptrace_viewos = ptrace_viewos_mask;
	while (1) {
		int c;
		int option_index = 0;
		c=getopt_long(argc,argv,"+p:o:hvnx",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'h': 
				usage(argv[0]);
				break;
			case 'v': 
				version(1);
				exit(0);
				break;
			case 'p': 
				preadd(&prehead,optarg);
				break;
			case 'o':{
						if (optarg==NULL){
							fprintf(stderr, "%s: must specify an argument after -o\n",argv[0]);
							break;
						}
						gdebug_set_ofile(optarg);
					 }
					 break;
			case 'n':
					 want_ptrace_multi = 0;
					 want_ptrace_vm = 0;
					 want_ptrace_viewos = 0;
					 break;
			case 0x100:
					 want_ptrace_multi = 0;
					 break;
			case 0x101:
					 want_ptrace_vm = 0;
					 break;
			case 0x102:
					 want_ptrace_viewos = 0;
					 break;
		}
	}
	
	if (has_ptrace_multi || ptrace_vm_mask || ptrace_viewos_mask)
	{
		fprintf(stderr, "This kernel supports: ");
		if (has_ptrace_multi)
			fprintf(stderr, "PTRACE_MULTI ");
		if (ptrace_vm_mask)
			fprintf(stderr, "PTRACE_SYSVM ");
		if (ptrace_viewos_mask)
			fprintf(stderr, "PTRACE_VIEWOS");
		fprintf(stderr, "\n");
	}
	
	if (has_ptrace_multi || ptrace_vm_mask || ptrace_viewos_mask ||
			want_ptrace_multi || want_ptrace_vm || want_ptrace_viewos)
	{
		fprintf(stderr, "%s will use: ", UMVIEW_NAME);	
		if (want_ptrace_multi)
			fprintf(stderr,"PTRACE_MULTI ");
		if (want_ptrace_vm)
			fprintf(stderr,"PTRACE_SYSVM ");
		if (want_ptrace_viewos)
			fprintf(stderr,"PTRACE_VIEWOS");
		if (!want_ptrace_multi && !want_ptrace_vm && !want_ptrace_viewos)
			fprintf(stderr,"nothing");
		fprintf(stderr,"\n\n");
	}
	
	has_ptrace_multi = want_ptrace_multi;
	ptrace_vm_mask = want_ptrace_vm;
	ptrace_viewos_mask = want_ptrace_viewos;
	
	if (has_pselect) {
		sigset_t unblockchild;
		/* pselect needs a strange sixth arg */
		struct {
			sigset_t *ss;
			size_t sz;
		}psel6={&unblockchild,8};
		/* save current mask */
		sigprocmask(SIG_BLOCK,NULL,&unblockchild);
		/* capture main will block SIGCHLD */
		capture_main(argv+optind,1);
		setenv("_INSIDE_UMVIEW_MODULE","",1);
		do_preload(prehead);
		/* select() management */
		select_init();
		while (nprocs) {
			int max,n;
			FD_ZERO(&wset[0]);
			FD_ZERO(&wset[1]);
			FD_ZERO(&wset[2]);
			max=select_fill_wset(wset);
			/* pselect gets unblocked either by a file request or by
			 * a signal (SIGCHLD) */
			n = r_pselect6(max+1,&wset[0],&wset[1],&wset[2],NULL,&psel6);
			/* call tracehand anyway, if waitpid fails it returns here
			 * quite soon, it is useless to waste another syscall like sigpending*/
			tracehand();
			if (n > 0)
				select_check_wset(max,wset);
		}
	} else {
		sigset_t blockchild, oldset;
		sigemptyset(&blockchild);
		sigaddset(&blockchild,SIGCHLD);
		/* Creation of the pipe for the signal handler */
		wake_tracer_init();

		capture_main(argv+optind,0);
		setenv("_INSIDE_UMVIEW_MODULE","",1);
		do_preload(prehead);

		/* select() management */
		select_init();
		while (nprocs) {
			int max,n;
			FD_ZERO(&wset[0]);
			FD_ZERO(&wset[1]);
			FD_ZERO(&wset[2]);
			sigprocmask(SIG_BLOCK,&blockchild,&oldset);
			max=select_fill_wset(wset);

			/* Add the tracerpipe and update max */
			max=add_tracerpipe_to_wset(max, &wset[0]);

			sigprocmask(SIG_SETMASK,&oldset,NULL);
			n = r_select(max+1,&wset[0],&wset[1],&wset[2],NULL);
			if (n > 0)
			{
				if (must_wake_tracer(&wset[0]))
				{
					// We received a message from the SIGCHLD handler, time to
					// start the real handler
					tracehand();
					continue;
				}
				sigprocmask(SIG_BLOCK,&blockchild,&oldset);
				select_check_wset(max,wset);
				sigprocmask(SIG_SETMASK,&oldset,NULL);
			}
		}
	}
	return first_child_exit_status;
}

