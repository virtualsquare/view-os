/*   
 *   This is part of Remote System Call (RSC) Library.
 *
 *   tests.h: list of the tests done
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

#ifndef __TESTS_HEADER__
#define __TESTS_HEADER__
#include "aconv.h"

void *test_client(void *fdp);
void *test_server(void *fdp);


void test_list(void);
void test_type_equality(void);
void test_ioctl_mngmt_client(int fd);
void test_ioctl_mngmt_server(int fd);

void test_libaconv_client(int fd, enum arch client_arch, enum arch server_arch);
void test_libaconv_server(int fd, enum arch client_arch, enum arch server_arch);

void test_syscall_exec_client(int fd, enum arch client_arch, enum arch server_arch);
void test_syscall_exec_server(int fd, enum arch client_arch, enum arch server_arch);

#endif /* __TESTS_HEADER__ */
