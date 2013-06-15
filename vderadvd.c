/*   
 *   vderadvd.c: VDE router advertisement daemon
 *   
 *   Copyright 2012 Renzo Davoli - Virtual Square Team 
 *   University of Bologna - Italy
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
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/stat.h>

static int logok=0;
static int daemonize; // daemon mode
static int verbose;
static char *pidfile;
static char pidfile_path[PATH_MAX];
static char *progname;
void printlog(int priority, const char *format, ...);

unsigned char buf[2048];

unsigned char ff0202[]=
{0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
unsigned char ff0201[]=
{0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
unsigned char mcast1[]={0x33,0x33,0x00,0x00,0x00,0x01};
unsigned char MAC[6];
unsigned char srcaddr[]=
{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00};
unsigned char ipv6head[]={
	0x60,0x00,0x00,0x00, /*IPv6 */
	0x00,0x38, /*length=56*/
	0x3a, /* icmpv6 */
	0xff /* hop limit */};
unsigned char icmphead[]={
	0x86,0x00,/* RA code 0 */
	0x00,0x00,/*checksum */
	0x40,0x00,0x01,0x2c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x78,0x03,0x04,0x40,0xc0,
	0x00,0x00,0x01,0x2c,0x00,0x00,0x00,0xb4,0x00,0x00,0x00,0x00};
unsigned char sourcelink[]={
	0x01,0x01};

unsigned char nexheader[]={0x00,0x00,0x00,0x3A};
unsigned char len[]={0x00,0x00,0x00,0x38};
void checksum(unsigned char *icmp)
{
	unsigned long sum=0;
	unsigned short *add;
	int i;
	add=(unsigned short *) srcaddr;
	for (i=0; i<8; i++)
		sum += add[i];
	add=(unsigned short *) ff0201;
	for (i=0; i<8; i++)
		sum += add[i];
	add=(unsigned short *) nexheader;
	for (i=0; i<2; i++)
		sum += add[i];
	add=(unsigned short *) len;
	for (i=0; i<2; i++)
		sum += add[i];
	add=(unsigned short *) icmp;
	for (i=0; i<(0x38>>1); i++)
		sum += add[i];
	while (sum >> 16)
		sum = (sum & 0xffffUL) + (sum >> 16);
	//printf("SUM %x\n",sum);
	icmp[2] = ~sum;
	icmp[3] = (~sum) >> 8;
}

void sendra(VDECONN *v, unsigned char *prefix)
{
	if (verbose)
		printlog(LOG_DEBUG, "Sending out RA");
	memcpy(buf,mcast1,sizeof(mcast1));
	memcpy(buf+0x6,MAC,sizeof(MAC));
	buf[0xc]=0x86;buf[0xd]=0xdd; /* IPv6 */
	memcpy(buf+0xe,ipv6head,sizeof(ipv6head));
	memcpy(buf+0x16,srcaddr,16);
	memcpy(buf+0x26,ff0201,16);
	memcpy(buf+0x36,icmphead,sizeof(icmphead));
	memcpy(buf+0x56,prefix,16);
	memcpy(buf+0x66,sourcelink,sizeof(sourcelink));
	memcpy(buf+0x68,MAC,sizeof(MAC));
	checksum(buf+0x36);
	vde_send(v,buf,110,0);
}

#if 0
void printaddr(unsigned char *a)
{
	int i;
	for (i=0;i<16;i++) 
		printf("%02x%s",a[i],(i%3==3)?":":"");
	printf("\n");
}
#endif

void usage(void)
{
	fprintf(stderr,"Usage: %s OPTIONS prefix sw [sw..]\n"
			"\t--help|-h\n"
			"\t--daemon|-d\n"
			"\t--pidfile pidfile\n"
			"\t--verbose|-v\n",
			progname);
	exit(1);
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority,format,arg);
	else {
		fprintf(stderr,"%s: ",progname);
		vfprintf(stderr,format,arg);
		fprintf(stderr,"\n");
	}
	va_end (arg);
}

static void save_pidfile()
{
	if(pidfile[0] != '/')
		strncat(pidfile_path, pidfile, PATH_MAX - strlen(pidfile_path));
	else
		strcpy(pidfile_path, pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

int main(int argc, char *argv[])
{
	int ip1,ip2,ip3,ip4;
	time_t now;
	time_t old=0;
	unsigned char prefix[16];
	int i;
	int nsw;
#define PIDFILEARG 131
	static struct option long_options[] = {
		{"help",0 , 0, 'h'},
		{"daemon",0 , 0, 'd'},
		{"pidfile", 1, 0, PIDFILEARG},
		{"verbose",0 , 0, 'v'},
		{0,0,0,0}
	};
	int option_index;
	progname=argv[0];
	while(1) {
		int c;
		c = getopt_long (argc, argv, "hdv",
				long_options, &option_index);
		if (c<0)
			break;
		switch (c) {
			case 'h':
				usage();
				break;
			case 'd':
				daemonize=1;
				break;
			case 'v':
				verbose=1;
				break;
			case PIDFILEARG:
				pidfile=strdup(optarg);
				break;
			default:
				usage();
				break;
		}
	}
	if (argc-optind < 2)
		usage();

	if (daemonize) {
		openlog(basename(progname), LOG_PID, 0);
		logok=1;
		syslog(LOG_INFO,"%s started",progname);
	}
	/* saves current path in pidfile_path, because otherwise with daemonize() we
	 * forget it */
	if(getcwd(pidfile_path, PATH_MAX-1) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	strcat(pidfile_path, "/");
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s",strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile();
	nsw=argc-optind-1;
	struct pollfd pfd[nsw];
	VDECONN *sw[nsw];
	struct addrinfo *res;
	static struct addrinfo hints={.ai_family=AF_INET6};
	int gaierr;
	if ((gaierr=getaddrinfo(argv[optind],NULL,&hints,&res))!=0) {
		printlog(LOG_ERR,"prefix: \n",gai_strerror(gaierr));
		exit(1);
	}           
	struct sockaddr_in6 *sock6=(struct sockaddr_in6 *)res->ai_addr;
	memset(prefix,0,sizeof(prefix));
	memcpy(&prefix,&(sock6->sin6_addr),8);

//	sscanf(argv[optind],"%x:%x:%x:%x",&ip1,&ip2,&ip3,&ip4);
	for (i=0; i<nsw; i++) {
		printf("%s nsw \n",argv[optind+1+i]);
		sw[i]=vde_open(argv[optind+1+i],"VDE radv daemon",NULL);
		if (sw[i]==NULL) {
			printlog(LOG_ERR,"Switch %s: %s",argv[optind+1+i],strerror(errno));
			exit(1);
		}
		pfd[i].fd=vde_datafd(sw[i]);
		pfd[i].events=POLLIN;
	}
	/*memset(prefix,0,sizeof(prefix));
	prefix[0]=ip1>>8; prefix[1]=ip1;
	prefix[2]=ip2>>8; prefix[3]=ip2;
	prefix[4]=ip3>>8; prefix[5]=ip3;
	prefix[6]=ip4>>8; prefix[7]=ip4;*/
	time(&now);
	srand((int)now);
	MAC[0]=0x06; srcaddr[0x8]=0x04;
	MAC[1]=srcaddr[0x9]=rand();
	MAC[2]=srcaddr[0xa]=rand();
	MAC[3]=srcaddr[0xd]=rand();
	MAC[4]=srcaddr[0xe]=rand();
	MAC[5]=srcaddr[0xf]=rand();

	while(1) {
		int x=poll(pfd,nsw,1000);
		for (i=0; i<nsw; i++) {
			if (pfd[i].revents & POLLIN) {
				int n=vde_recv(sw[i],buf,2048,0);
				if (n==0) return;
				//printf("%d\n",n);
				if (n<=54) continue;
				if (buf[0xc]==0x86 && buf[0xd]==0xdd) {
					//printf("IPV6\n");
					//printaddr(buf+0x26);
					if (memcmp(buf+0x26,ff0202,16)==0 && buf[0x36]==0x85)
						sendra(sw[i],prefix);
				}
			}
		}
		time(&now);
		if ((old>>6) != (now>>6)) {
			for (i=0; i<nsw; i++) 
				sendra(sw[i],prefix);
			old=now;
		}
	}
}
