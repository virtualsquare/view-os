<%#
     This is part of RSC file generator program
  
     rsc_to_nr.h: template file for __RSC_* to __NR_* constants 
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
<% @@filename = "rsc_to_nr.h" %>
<% @@overwrite_existing_copy  = false %>
/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   <%=@@filename%>: __RSC_* to __NR_* constants conversion header 
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
#ifndef __RSC_TO_NR_HEADER__
#define __RSC_TO_NR_HEADER__
#include <stdlib.h>
#include <linux/net.h>
#include "rsc_consts.h"

<%= nr_x86.table_rsc_to_arch %>

<%= nr_x86_64.table_rsc_to_arch %>

<%= nr_ppc.table_rsc_to_arch %>

#endif /* __RSC_TO_NR_HEADER__ */
