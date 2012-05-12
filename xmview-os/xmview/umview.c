/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umview.c: main
 *   
 *   Copyright 2005 Renzo Davoli University of Bologna - Italy
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
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#ifdef OLDVIRSC
#include <linux/sysctl.h>
#endif
#include <config.h>
#include <loginshell.h>
#include<errno.h>

#ifndef _VIEWOS_UM
#define _VIEWOS_UM
#endif

#include "defs.h"
#include "umview.h"
#include "capture_um.h"
#include "sctab.h"
#include "services.h"
#include "um_select.h"
#include "um_services.h"
#include "ptrace_multi_test.h"
#include "mainpoll.h"
#include "gdebug.h"

#define COMMON_OPTSTRING "+p:f:hvnxqV:srD::ckK"
#ifdef GDEBUG_ENABLED
#	define GDEBUG_OPT "o:C"
#else
#	define GDEBUG_OPT ""
#endif
#ifdef _UM_PTRACE
# define PTRACE_OPT "t"
#else
# define PTRACE_OPT ""
#endif
#define OPTSTRING COMMON_OPTSTRING GDEBUG_OPT PTRACE_OPT

int _umview_version = 2; /* modules interface version id.
										modules can test to be compatible with
										um-viewos kernel*/
unsigned int has_ptrace_multi;
unsigned int ptrace_vm_mask;
unsigned int ptrace_sysvm_tag;
unsigned int quiet = 0;
unsigned int printk_current_level = PRINTK_STARTUP_LEVEL;
unsigned int secure = 0;
unsigned int hostcmdok = 0;
unsigned int doptrace = 0;
unsigned int realrecursion = 0;
unsigned int secretdebug = 0;
#ifdef _UM_PTRACE
unsigned int ptraceemu = 0;
#endif
static char *viewname;
static char *console_ptyname;

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

/* virtual syscall for the underlying umview */
#ifdef OLDVIRSC
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
#else
static long int_virnsyscall(long virscno,int n,long arg1,long arg2,long arg3,long arg4,long arg5,long arg6) {
	long args[6]={arg1,arg2,arg3,arg4,arg5,arg6};
	return native_syscall(__NR_pivot_root,NULL,n,virscno,args);
}
#endif

/* preload of modules */
static int do_preload(struct prelist *head)
{
	if (head != NULL) {
		int rv=do_preload(head->next);
		if (add_service(head->module,0) < 0) {
			printk(KERN_NOTICE "module preload %s",strerror(errno));
			return -1 ;
		} else
			return rv;
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

/* preload for nexted umview (it is a burst of um_add_module) */
static int do_preload_recursive(struct prelist *head)
{
	if (head != NULL) {
		do_preload_recursive(head->next);
		int_virnsyscall(__NR_UM_SERVICE,3,ADD_SERVICE,(long)head->module,0,0,0,0);
		free(head);
		return 0;
	} else
		return 0;
}

static void do_set_viewname_recursive(char *viewname)
{
	if (viewname) {
		int_virnsyscall(__NR_UM_SERVICE,2,VIEWOS_SETVIEWNAME,(long)viewname,0,0,0,0);
	}
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
			"  -q, --quiet               suppress some additional output\n"
			"  -V name, --viewname name  set the view name\n"
			"  -f file, --rc file        set rc file\n"
			"  -p file, --preload file   load plugin named `file' (must be a .so)\n"
#ifdef GDEBUG_ENABLED
			"  -o file, --output file    send debug messages to file instead of stderr\n"
			"  -C --color                enable ansi color on debug\n"
#endif
			"  -x, --nonesting           do not permit module nesting\n"
			"  -n, --nokernelpatch       avoid using kernel patches\n"
			"  --nokmulti                avoid using PTRACE_MULTI\n"
			"  --noksysvm                avoid using PTRACE_SYSVM\n"
			"  --nokviewos               avoid using PTRACE_VIEWOS\n\n"
			"  -s, --secure              force permissions and capabilities\n"
			"  -r, --realrecursion       real nested umview based on ptrace\n"
#ifdef _UM_PTRACE
			"  -t, --ptraceemu           emulation of ptrace\n"
#endif
			"  -c, --hostcmd             permit um_hostcmd\n"
			"  -k, --console             activate remote monitor console\n"
			"  -K, --quietconsole        like -k + suppress local output\n"
			,s);
	exit(0);
}

static struct option long_options[] = {
	{"preload",1,0,'p'},
	{"rc",1,0,'f'},
#ifdef GDEBUG_ENABLED
	{"output",1,0,'o'},
	{"color",0,0,'C'},
#endif
	{"version",0,0,'v'},
	{"quiet",0,0,'q'},
	{"viewname",1,0,'V'},
	{"help",0,0,'h'},
	{"nonesting",0,0,'x'},
	{"nokernelpatch",0,0,'n'},
	{"nokmulti",0,0,0x100},
	{"noksysvm",0,0,0x101},
	{"nokviewos",0,0,0x102},
	{"secure",0,0,'s'},
	{"realrecursion",0,0,'r'},
#ifdef _UM_PTRACE
	{"ptraceemu",0,0,'t'},
#endif
	{"hostcmd",0,0,'c'},
	{"console",0,0,'k'},
	{"quietconsole",0,0,'K'},
	{0,0,0,0}
};

/* pure_libc loading (by reloading the entire umview) */
static void load_it_again(int argc,char *argv[],int login)
{
	int nesting=1;
	optind=1;
	while (1) {
		int c;
		int option_index = 0;
		/* some options must be parsed before reloading */
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);

		if (c == -1) break;
		switch (c) {
			case 'h':
				usage(argv[0]);
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
			if (login)
				argv[0]="--umview-login";
			else
				argv[0]="--umview";
			execv(path,argv);
			/* useless cleanup */
			free(path);
		}
	}
}

/* recursive umview invocation (umview started inside a umview machine) */
static void umview_recursive(int argc,char *argv[])
{
	char *rcfile=NULL;
	if (argc < 2)
	{
		usage(argv[0]);
		exit(1);
	}

	optind=1;
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
			case 'f':
				rcfile=strdup(optarg);
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
	if (rcfile==NULL)
		asprintf(&rcfile,"%s/%s",getenv("HOME"),".viewosrc");
	capture_execrc("/etc/viewosrc","nested");
	if (rcfile != NULL && *rcfile != 0)
		capture_execrc(rcfile,"nested");
	do_preload_recursive(prehead);
	do_set_viewname_recursive(viewname);
	/* exec the process */
	execvp(*(argv+optind),argv+optind);
	exit(-1);
}

#define UMCONSOLEWRAP LIBEXECDIR "/umconsolewrap"
static void activate_console(char c)
{
	int pty;
	int pid;
	if ((pty = open("/dev/ptmx", O_RDWR|O_NOCTTY)) < 0) {
		printk(KERN_ERR "Unable to open /dev/ptmx (console): %s",strerror(errno));
		return;
	}
	if (unlockpt(pty) < 0) {
		printk(KERN_ERR "Unable to unlockpt (console): %s",strerror(errno));
		return;
	}
	if (grantpt(pty) < 0) {
		printk(KERN_ERR "Unable to grantpt (console): %s",strerror(errno));
		return;
	}
	console_ptyname=strdup(ptsname(pty));
	//printf("Opened a new pty: %s\n", console_ptyname);

	if ((pid=fork())>0)
	{
		//printf("FORK\n");
		char *spty,*socketname;
		asprintf(&spty,"%d%c",pty,(c=='K')?'q':' ');
		asprintf(&socketname,"/tmp/.umview-console%d",pid);
		unsetenv("LD_PRELOAD");
		//printf("console exec %s\n",spty);
		execl(UMCONSOLEWRAP,"umconsolewrap",socketname,spty,"stdout",(char *)NULL);
		printk(KERN_CRIT "Unable to run the console wrapper: %s",strerror(errno));
		exit(1);
	} 
	//setsid();    /* become session leader and */
	close(pty);
}

static void redirect_on_console(void)
{
	int fd;
	/* lose controlling tty */
	setsid();    /* become session leader and */
	//printf("sedsid %d %s %s\n",rv,strerror(errno),console_ptyname);
	fd = open(console_ptyname, O_RDWR);
	if (fd < 0) {
		printk(KERN_ERR "Unable to open console pts: %s",strerror(errno));
		return;
	} else {
		dup2(fd,0);
		dup2(fd,1);
		dup2(fd,2);
		ioctl(fd,TIOCSCTTY,0);
	}
}

/* user recursion must be recognized very early */
static void umview_earlyargs(int argc,char *argv[])
{
	optind=1;
	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'r':
				realrecursion = 1;
				break;
			case 'D':
				if (optarg == 0 || *optarg == 0)
					secretdebug=1;
				else
					secretdebug=atoi(optarg);
				break;
		}
	}
}

/* UMVIEW MAIN PROGRAM */
int main(int argc,char *argv[])
{
	char *rcfile=NULL;
	unsigned int want_ptrace_multi, want_ptrace_vm, want_ptrace_viewos;
	sigset_t unblockchild;
	if (argc == 1 && argv[0][0] == '-' && argv[0][1] != '-') /* login shell */
		loginshell_view();
	/* try to set the priority to -11 provided umview has been installed
	 * setuid. it is effectiveless elsewhere */
	r_setpriority(PRIO_PROCESS,0,-11);
	/* if it was setuid, return back to the user status immediately,
	 * for safety! */
	r_setuid(getuid());
	/* set early args */
	umview_earlyargs(argc,argv);
	/* Check these cases only when *not* reloaded for purelibc */
	if (strncmp(argv[0],"--umview",8)!=0) {
	/* if this is a nested invocation of umview, notify the umview monitor
	 * and execute the process, 
	 * try the nested invocation notifying virtual syscall, 
	 * if it succeeded it is actually a nested invocation,
	 * otherwise nobody is notified and the call fails*/
		if (!realrecursion &&
				int_virnsyscall(__NR_UM_SERVICE,1,RECURSIVE_VIEWOS,0,0,0,0,0) >= 0)
			umview_recursive(argc,argv);	/* do not return!*/
		/* umview loads itself twice if there is pure_libc, to trace module 
		 * generated syscalls, this condition manages the first call */
		load_it_again(argc,argv,isloginshell(argv[0]));	/* do not return (when purelibc and not -x)!*/
	}

	if (argc < 2)
	{
		usage(argv[0]);
		exit(1);
	}

	optind=1;
	argv[0]="umview";
	/* set up the scdtab */
	scdtab_init();
	/* test the ptrace support */
	has_ptrace_multi=test_ptracemulti(&ptrace_vm_mask,&ptrace_sysvm_tag);
	want_ptrace_multi = has_ptrace_multi;
	want_ptrace_vm = ptrace_vm_mask;
	/* option management */
	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, OPTSTRING, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
			case 'h': /* help */
				usage(argv[0]);
				break;
			case 'v': /* version */
				version(1);
				exit(0);
				break;
			case 'V':
				viewname=strdup(optarg);
				break;
			case 'p': /* module preload, here the module requests are just added to
			             a data structure */
				preadd(&prehead,optarg);
				break;
			case 'f':
				rcfile=strdup(optarg);
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
			case 'C':
					 gdebug_set_color(COLOR_ENABLE);
					 break;
#endif
			case 'n': /* do not use kernel extensions */
					 want_ptrace_multi = 0;
					 want_ptrace_vm = 0;
					 want_ptrace_viewos = 0;
					 break;
			case 's':
					 secure=1;
					 break;
			case 'c':
					 hostcmdok=1;
					 break;
			case 0x100: /* do not use ptrace_multi */
					 want_ptrace_multi = 0;
					 break;
			case 0x101: /* do not use ptrace_vm */
					 want_ptrace_vm = 0;
					 break;
			case 0x102: /* do not use ptrace_viewos */
					 want_ptrace_viewos = 0;
					 break;
#ifdef _UM_PTRACE
			case 't':
					 ptraceemu = 1;
					 break;
#endif
			case 'K':
			case 'k':
					 activate_console(c);
					 break;
		}
	}
	
	if (!quiet)
	{
		if (has_ptrace_multi || ptrace_vm_mask)
		{
			fprintf(stderr, "This kernel supports: ");
			if (has_ptrace_multi)
				fprintf(stderr, "PTRACE_MULTI ");
			if (ptrace_vm_mask)
				fprintf(stderr, "PTRACE_SYSVM ");
			fprintf(stderr, "\n");
		}

		if (has_ptrace_multi || ptrace_vm_mask ||
				want_ptrace_multi || want_ptrace_vm || want_ptrace_viewos)
		{
			fprintf(stderr, "%s will use: ", UMVIEW_NAME);	
			if (want_ptrace_multi)
				fprintf(stderr,"PTRACE_MULTI ");
			if (want_ptrace_vm)
				fprintf(stderr,"PTRACE_SYSVM ");
			if (want_ptrace_viewos)
				fprintf(stderr,"PTRACE_VIEWOS ");
			if (!want_ptrace_multi && !want_ptrace_vm && !want_ptrace_viewos)
				fprintf(stderr,"nothing");
			fprintf(stderr,"\n\n");
		}
	}

	has_ptrace_multi = want_ptrace_multi;
	ptrace_vm_mask = want_ptrace_vm;
	
	if (rcfile==NULL && !isloginshell(argv[0]))
		asprintf(&rcfile,"%s/%s",getenv("HOME"),".viewosrc");

	if (quiet) {
		setenv("_VIEWOS_QUIET","1",1);
		printk_current_level = PRINTK_QUIET_LEVEL; /* warnings or errors only */
	}

	sigprocmask(SIG_BLOCK,NULL,&unblockchild);
	pcb_inits(1);
	capture_main(argv+optind,rcfile);
	if(console_ptyname) redirect_on_console();
	setenv("_INSIDE_VIEWOS_MODULE","",1);
	do_preload(prehead);
	do_set_viewname(viewname);
	while (nprocs) {
		mp_ppoll(&unblockchild);
		tracehand();
	}
	pcb_finis(1);
	return first_child_exit_status;
}

