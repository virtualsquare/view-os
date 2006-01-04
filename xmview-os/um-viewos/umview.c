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
#include "defs.h"
#include "capture_sc.h"
#include "sctab.h"
#include "services.h"
#include "um_select.h"
#include "um_services.h"
#include "ptrace_multi_test.h"

int _lwip_version = 1; /* modules interface version id.
													modules can test to be compatible with
													um-viewos kernel*/
int has_ptrace_multi;
extern int nprocs;
char *preload;

static void usage(char *s) {
	fprintf(stderr,"Usage: \n"
			"\t%s -h\n"
			"\t%s -help     : print this help message\n"
			"\t%s [ -p -o -n ] command\n"
			"\t%s [ -preload -output -nokernelpatch ] command\n",
			s,s,s,s);
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
	has_ptrace_multi=test_ptracemulti();
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"preload",1,0,'p'},
			{"output",1,0,'o'},
			{"help",0,0,'h'},
			{"nokernelpatch",0,0,'n'},
			{0,0,0,0}
		};
		c=getopt_long(argc,argv,"+p:o:hn",long_options,&option_index);
		if (c == -1) break;
		switch (c) {
			case 'h': 
				usage(argv[0]);
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
			// write stdout to file specified by an argument
			case 'o':{
						if( optarg==NULL){
							printf("%s: must specify an argument after -o\n",argv[0]);
							break;
						}
						close(STDOUT_FILENO);
						if( open(optarg,O_WRONLY | O_CREAT | O_TRUNC,0666)<1 ){
							perror(optarg);
							exit(-1);
						}
					 }
					 break;
			case 'n':
					 has_ptrace_multi=0;
					 break;
		}
	}
	if (has_ptrace_multi > 0)
		fprintf(stderr,"Running with PTRACE_MULTI enabled\n");
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
