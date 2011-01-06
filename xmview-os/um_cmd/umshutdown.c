/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   umviewname.c 
 *   uname extension to view-os (umview)
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
 *   $Id: vuname.c 364 2007-06-11 08:56:36Z rd235 $
 *
 */   
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <config.h>
#include <um_lib.h>

void usage()
{
	fprintf(stderr, 
			"Usage: umshutdown [time]\n"
		  "Shutdown of xmview.\n"
			"\n");
	exit(2);
}

void termhandler(int signo)
{
}

int main(int argc, char *argv[])
{
	int wtime;
	if (um_check_viewos()==0) {
		fprintf(stderr,"This is a View-OS command. It works only inside a umview/kmview virtual machine\n");
		usage();
	}            
	if (argc == 1)
		wtime=30;
	else if (argc==2)
		wtime=atoi(argv[1]);
	else
		usage();
	daemon(1,1);
	signal(SIGTERM,termhandler);
	um_killall(SIGTERM);
	if (wtime>0)
		sleep(wtime);
	um_killall(SIGKILL);
	return 0;
}
