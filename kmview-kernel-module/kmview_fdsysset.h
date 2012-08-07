/*
 *
 * Copyright (C) 2007 Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Due to this file being licensed under the GPL there is controversy over
 *  whether this permits you to write a module that #includes this file
 *  without placing your module under the GPL.  Please consult a lawyer for
 *  advice before doing this.
 *
 */

#ifndef _KMVIEW_FDSYSSET_H
#define _KMVIEW_FDSYSSET_H

struct kmview_fdsysset {
	int ncopy;
	int nfd;
	fd_set fdset;
};

struct kmview_fdsysset *fdsysset_copy(struct kmview_fdsysset *fds);
struct kmview_fdsysset *fdsysset_set(int fd, struct kmview_fdsysset *fds);
struct kmview_fdsysset *fdsysset_clr(int fd, struct kmview_fdsysset *fds);
void fdsysset_free(struct kmview_fdsysset *fds);
int fdsysset_init(void);
void fdsysset_fini(void);

#ifndef FD_SETSIZE
#define FD_SETSIZE __FD_SETSIZE
#endif
#ifndef FD_ISSET
#define FD_ISSET(x,y) test_bit((x),(y)->fds_bits)
#endif
#ifndef FD_ZERO
#define FD_ZERO(x) memset((x),0,sizeof(*(x)))
#endif
#ifndef FD_SET
#define FD_SET(x,y) set_bit((x),(y)->fds_bits)
#endif
#ifndef FD_CLR
#define FD_CLR(x,y) clear_bit((x),(y)->fds_bits)
#endif

#endif
