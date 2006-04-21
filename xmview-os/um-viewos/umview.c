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
#include <signal.h>
#include "umview.h"
#include "defs.h"
#include "capture_sc.h"
#include "sctab.h"
#include "services.h"
#include "um_select.h"
#include "um_services.h"
#include "ptrace_multi_test.h"
#include "gdebug.h"

int _lwip_version = 1; /* modules interface version id.
													modules can test to be compatible with
													um-viewos kernel*/
unsigned int has_ptrace_multi;
unsigned int ptrace_vm_mask;
unsigned int ptrace_viewos_mask;

unsigned int want_ptrace_multi, want_ptrace_vm, want_ptrace_viewos;

extern int nprocs;
char *preload;


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
			"  -n, --nokernelpatch       avoid using kernel patches\n"
			"  --nokmulti                avoid using PTRACE_MULTI\n"
			"  --nokvm                   avoid using PTRACE_SYSVM\n"
			"  --nokviewos               avoid using PTRACE_VIEWOS\n\n",
			s);
	exit(0);
}

int main(int argc,char *argv[])
{
	int c;
	fd_set wset[3];
	sigset_t blockchild, oldset;
	
	setpriority(PRIO_PROCESS,0,-11);
	setuid(getuid());
	sigemptyset(&blockchild);
	sigaddset(&blockchild,SIGCHLD);
	scdtab_init();
	has_ptrace_multi=test_ptracemulti(&ptrace_vm_mask,&ptrace_viewos_mask);
	want_ptrace_multi = has_ptrace_multi;
	want_ptrace_vm = ptrace_vm_mask;
	want_ptrace_viewos = ptrace_viewos_mask;
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"preload",1,0,'p'},
			{"output",1,0,'o'},
			{"help",0,0,'h'},
			{"nokernelpatch",0,0,'n'},
			{"nokmulti",0,0,0x100},
			{"nokvm",0,0,0x101},
			{"nokviewos",0,0,0x102},
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"+p:o:hvn",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'h': 
				usage(argv[0]);
				break;
			case 'v': 
				version(1);
				exit(0);
				break;
			case 'p': {
					  void *handle=open_dllib(optarg);
					  if (handle==NULL) {
						  fprintf(stderr, "%s\n",dlerror());
						  exit (-1);
					  } else 
						  set_handle_new_service(handle,0);
				  }
				  break;
			case 'o':{
						 FILE* new_ofile;
						if (optarg==NULL){
							fprintf(stderr, "%s: must specify an argument after -o\n",argv[0]);
							break;
						}
						new_ofile = fopen(optarg, "w");
						if (!new_ofile)
						{
							perror(optarg);
							exit(-1);
						}
						gdebug_set_ofile(new_ofile);
						/*
						close(STDOUT_FILENO);
						if( open(optarg,O_WRONLY | O_CREAT | O_TRUNC,0666)<1 ){
							perror(optarg);
							exit(-1);
						}
						*/
						
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
	
	capture_main(argv+optind);
	setenv("_INSIDE_UMVIEW_MODULE","",1);

	/* Creation of the pipe for the signal handler */
	wake_tracer_init();
	
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
		n = select(max+1,&wset[0],&wset[1],&wset[2],NULL);
		if (n > 0)
		{
			if (must_wake_tracer(&wset[0]))
			{
				// We received a message from the SIGCHLD handler, time to
				// start the real handler
				tracehand(0);
				continue;
			}
			sigprocmask(SIG_BLOCK,&blockchild,&oldset);
			select_check_wset(max,wset);
			sigprocmask(SIG_SETMASK,&oldset,NULL);
		}
	}
	/*
	{
		int i;
		void *hdl;
		for (i=0;i<0xff;i++)
			if ((hdl=get_handle_service(i)) != NULL)
				dlclose(hdl);
	}
	*/
	extern int first_child_exit_status;
	return first_child_exit_status;
}
