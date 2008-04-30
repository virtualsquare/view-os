# This is part of UMView
# The user-mode implementation of View-OS: A Process with a View
#
# Sample Python module that mimics the unreal testmodule
#
# Copyright 2008 Ludovico Gardenghi, University of Bologna, Italy
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

import os
import umpyew

def modInit():
	global t1, t2
	t1 = umpyew.tstTimestamp()
	t2 = umpyew.tstTimestamp()

def modCheckFun(*arg, **kw):
	if kw.has_key('path') and kw['path'][0:7] == '/unreal':
		e = umpyew.tstMatchingEpoch(t2)
		if e == 0:
			return umpyew.tstMatchingEpoch(t1)
		return e
	return 0

def unwrap(path):
	if type(path) == str:
		return path[0] + path[8:]
	else:
		return path

############################
# System calls definitions #
############################

# These functions can be safely mapped to the corresponding real syscalls.
sysRead = sysWrite = sysClose = sysFstat64 = sysLseek = None

def sysGenericPath(path, *arg, **kw):
	try:
		rv = getattr(os, kw['cname'])(unwrap(path), *arg)
		if rv == None:
			return (0, 0)
		elif type(rv) == bool:
			# syscalls like os.access() return True or False. Since True means
			# success, and for UNIX syscalls succes is 0, we must negate the
			# value (True is represented as 1 and False as 0).
			return (not rv, 0)
		else:
			return (rv, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysOpen = sysRmdir = sysUnlink = sysAccess = sysMkdir = sysChmod = sysGenericPath

# Manages also symlink()
def sysLink(oldpath, newpath, **kw):
	try:
		if kw['cname'] == 'symlink':
			os.symlink(oldpath, unwrap(newpath))
		else: # link
			os.link(unwrap(oldpath), unwrap(newpath))
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysSymlink = sysLink

# manages stat64, lstat64()
def sysStats(path, **kw):
	try:
		os.stat_float_times(False)
		return (0, 0, getattr(os, kw['cname'].rstrip('64'))(unwrap(path)))
	except OSError, (errno, strerror):
		return (-1, errno)

sysStat64 = sysLstat64 = sysStats

def sysStatfs64(**kw):
	try:
		return (0, 0, os.statvfs(unwrap(path)))
	except OSError, (errno, strerror):
		return (-1, errno)

def sysReadlink(path, bufsiz, **kw):
	try:
		tmplink = os.readlink(unwrap(path))
		return (min(bufsiz, len(tmplink)), 0, tmplink[0:bufsiz])
	except OSError, (errno, strerror):
		return (-1, errno)

def sysUtimes(path, atime, mtime, **kw):
	try:
		os.utime(unwrap(path), (atime[0] + atime[1]/1000000.0, mtime[0] + mtime[1]/1000000.0))
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysUtime = sysUtimes

