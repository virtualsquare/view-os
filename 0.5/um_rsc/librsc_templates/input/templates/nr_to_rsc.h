<%#
     This is part of RSC file generator program
  
     nr_to_rsc.h: template file for __NR_* to __RSC_* constants 
                  conversion header 
     
     Copyright (C) 2007 Andrea Forni
     
     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License, version 2, as
     published by the Free Software Foundation.
  
     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.
  
     You should have received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc.,
     51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
%>
<% @@librsc_relative_path = "/src/include/" %>
<% @@filename = "nr_to_rsc.h" %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: __NR_* to __RSC_* constants conversion header 
 *   
 *   Copyright (C) 2007 Andrea Forni
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
 */
#ifndef __NR_TO_RSC_HEADER__
#define __NR_TO_RSC_HEADER__
#include <stdlib.h>
#include "rsc_consts.h"

/* SYS_ values are equal in each architecture,
 * so a single table is sufficent. */
#define SYS_TO_RSC_SIZE	((sizeof(sys_to_rsc))/(sizeof(int32_t)))
int32_t sys_to_rsc[] = {
	/* 0. Isn't used */ __RSC_ERROR,
	/* 1. SYS_SOCKET */ __RSC_socket,
	/* 2. SYS_BIND	*/ __RSC_bind,
	/* 3. SYS_CONNECT */ __RSC_connect,
	/* 4. SYS_LISTEN */ __RSC_listen,
	/* 5. SYS_ACCEPT */ __RSC_accept,
	/* 6. SYS_GETSOCKNAME */ __RSC_getsockname,
	/* 7. SYS_GETPEERNAME */ __RSC_getpeername,
	/* 8. SYS_SOCKETPAIR */ __RSC_socketpair,
	/* 9. SYS_SEND */ __RSC_send,
	/* 10. SYS_RECV */ __RSC_recv,
	/* 11. SYS_SENDTO */ __RSC_sendto,
	/* 12. SYS_RECVFROM */ __RSC_recvfrom,
	/* 13. SYS_SHUTDOWN */ __RSC_shutdown,
	/* 14. SYS_SETSOCKOPT */ __RSC_setsockopt,
	/* 15. SYS_GETSOCKOPT */ __RSC_getsockopt,
	/* 16. SYS_SENDMSG */ __RSC_sendmsg,
	/* 17 SYS_RECVMSG */ __RSC_recvmsg
};
 
<%= nr_x86.table_nr_to_rsc %>

<%= nr_x86_64.table_nr_to_rsc %>

<%= nr_ppc.table_nr_to_rsc %>

#endif /* __NR_TO_RSC_HEADER__ */
