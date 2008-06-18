/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   client_server.h: client and server setup functions
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

#ifndef __CLIENT_SERVER_HEADER__
#define __CLIENT_SERVER_HEADER__

int setup_client(char *server_addr, char *server_port);
int setup_server(short int server_port);
#endif /* __CLIENT_SERVER_HEADER__ */
