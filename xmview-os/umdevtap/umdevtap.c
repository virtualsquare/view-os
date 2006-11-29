/*   This is part of um-ViewOS
 *   The user-mode implementation of OSVIEW -- A Process with a View
 *
 *   UMDEVMBR: Virtual Device to access Disk Images
 *   (using the standard IBM-PC partition scheme based on MBR/Extended MBR)
 *
 *    Copyright (C) 2006  Renzo Davoli <renzo@cs.unibo.it>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
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
#include <fcntl.h>
#include <string.h>
#include <umdev.h>
#include <stdlib.h>
#include <errno.h>
#include <libvdeplug.h>
#include <sys/socket.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

struct umtap {
	VDECONN *conn;
	char *name;
};

static int umtap_open(char type, dev_t device, struct dev_info *di)
{
	struct umtap *umtap=malloc(sizeof(struct umtap));
	umtap->conn=NULL;
	umtap->name=NULL;
	di->fh=(uint64_t)((long) umtap);
}

static int umtap_read(char type, dev_t device, char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct umtap *umtap=(struct umtap *)((long) di->fh);
	if (umtap->conn) {
		return vde_recv(umtap->conn,buf,len,0);
	} else
		return -ENOTCONN;
}

static int umtap_write(char type, dev_t device, const char *buf, size_t len, loff_t pos, struct dev_info *di)
{
	struct umtap *umtap=(struct umtap *)((long) di->fh);
	if (umtap->conn) {
		return vde_send(umtap->conn,buf,len,0);
	} else
		return -ENOTCONN;
}

static int umtap_release(char type, dev_t device, struct dev_info *di)
{
	struct umtap *umtap=(struct umtap *)((long) di->fh);
	if (umtap->conn) {
		vde_close(umtap->conn);
	} else
		return -ENOTCONN;
}

static int umtap_init(char type, dev_t device, char *path, unsigned long flags, char *args, struct umdev *devhandle)
{
/* TODO parse args */
	umdev_setprivatedata(devhandle,strdup(path));
}

static int umtap_fini(char type, dev_t device, struct umdev *devhandle)
{
	char *path=umdev_getprivatedata(devhandle);
	free(path);
}

static int umtap_ioctl(char type, dev_t device, int req, void * arg, struct dev_info *di)
{
	char *path=umdev_getprivatedata(di->devhandle);
	struct umtap *umtap=(struct umtap *)((long) di->fh);
	static tapcount;
	switch (req) {
		case TUNSETIFF:
			{
				struct ifreq *ifr=arg;
				if (umtap->conn != NULL)
					return -EADDRINUSE;
				if (ifr->ifr_flags & IFF_TAP) {
					char name[IFNAMSIZ+1];
					char comment[80+IFNAMSIZ+1];
					if (ifr->ifr_name[0] == 0) 
						sprintf(name,"tap%d",tapcount++);
					else
						strncpy(name,ifr->ifr_name,IFNAMSIZ);
				  name[IFNAMSIZ]=0;
					snprintf(comment,80+IFNAMSIZ,"umdevtap PID:%d %s\n",um_mod_getpid(),name);
					umtap->conn=vde_open(path,comment,NULL);
					if (umtap->conn) 
						umtap->name=strdup(name);
				} else
					return -EINVAL;
			}
			break;
		default: return -EINVAL;
	}
	return 0;
}

static int umtap_ioctl_params(char type, dev_t device, int req, struct umdev *devhandle)
{
	switch (req) {
		/*case BLKROSET: return (sizeof(int) | IOCTL_R);
			case BLKROGET: return (sizeof(int) | IOCTL_W);*/
		case TUNSETIFF: return (sizeof(struct ifreq) | IOCTL_W | IOCTL_R);
		default: return 0;
	}
}

static int umtap_select_register(char type, dev_t device, 
		voidfun cb, void *arg, int how, struct dev_info *di)
{
	struct umtap *umtap=(struct umtap *)((long) di->fh);
	if (umtap->conn) {
		int rv=um_mod_select_register(cb,arg,vde_datafd(umtap->conn),how);
		/*
		if (cb) {
			if (rv == 0)
				rv=um_select_register(cb,arg,vde_datafd(umtap->conn),POLLIN|POLLERR);
			return rv;
		} else {
			if (rv == 0)
				rv=um_select_register(cb,arg,vde_datafd(umtap->conn),POLLIN|POLLERR);
			else
				um_select_register(cb,arg,vde_datafd(umtap->conn),POLLIN|POLLERR);
		}*/
		return rv;
	}
	else
		return 1;
}

struct umdev_operations umdev_ops={
	.open=umtap_open,
	.read=umtap_read,
	.write=umtap_write,
	.release=umtap_release,
	.init=umtap_init,
	.fini=umtap_fini,
	.ioctl=umtap_ioctl,
	.ioctlparms=umtap_ioctl_params,
	.select_register=umtap_select_register,
};


