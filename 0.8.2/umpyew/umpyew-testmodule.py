# This is part of UMView
# The user-mode implementation of View-OS: A Process with a View
#
# Sample (useless) Python module to be used with the umpyew UMView module.
# 
# $ umview -p umpyew,umpyew-testmodule command
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

# The module 'umpyew' must be included in order to have access to the
# following methods:
# 
# - tstTimestamp
# - tstMatchingEpoch
#
# More method will be provided (ideally the final umpyew module will provide
# all the public functions from module.h)
import umpyew

# This list can contain zero or more of the following:
# 'proc', 'module', 'mount' and corresponds to the ctlhs.
modCtlHistorySet = ['proc'];

# If you have any initalization, put it here.
def modInit():
	print "Init!"
	global ts
	ts = umpyew.tstTimestamp()

# The same for finalization.
def modFini():
	print "Fini!"

# This is the same as the ctl function of regular C modules. At present only
# the standard commands are supported (i.e. not the custom ones).
def modCtl(cls, cmd, cmdArgs):
	print "class:", cls, "command:", cmd, "args:", cmdArgs
	# Just an example
	if cls == 'proc':
		if cmd == 'add':
			print "New process with id %d" % cmdArgs[0]
		elif cmd == 'rem':
			print "Process with id %d removed" % cmdArgs[0]
	return 0

# This is the standard check function that returns 0 or an epoch. kw
# contains only one key. Its name is one of 'path', 'socket', 'fstype', 'sc'
# (system call number) and 'binfmt'. Its value is as in regular C modules.
def modCheckFun(*arg, **kw):
	print kw
	if kw.has_key('path'):
		rv = umpyew.tstMatchingEpoch(ts)
		print "returning", rv
		return rv
	# Just examples
	elif kw.has_key('socket'):
		pass
	elif kw.has_key('fstype'):
		pass
	elif kw.has_key('sc'):
		pass
	elif kw.has_key('binfmt'):
		pass
	print "returning 0"
	return 0

# These functions are called from the umpyew module with the positional
# parameters corresponding to the parameters of the C system calls (except for
# pointers to structures to be filled, that are not passed) and with two
# dictionary parameters: 'cname' which contains the system call name and
# 'pyname' which contains the name used to call the Python method (e.g.
# 'sysOpen').

# The return value of the system call management functions must be a tuple
# with no less than 2 items. The minimal return value is composed by (retval,
# errno). Additional items can be inserted for returning additional data (as
# in stat or readlink syscalls).

# Setting a sysSomething to None is equivalent to calling
# SERVICESYSCALL(s, something, something)
# i.e the real system call will be called without accessing Python methods.

# This function manages system calls that does not need to return additional
# data. It works only for those syscalls whose C prototype matches the
# corrresponding one in Pyton os module as for parameters type and order.
# If you want to see how to change the arguments before calling, take a look
# at the unreal.py module.
def sysGeneric(*arg, **kw):
	print "Calling system call", kw['cname'], "with parameters", arg
	try:
		rv = getattr(os, kw['cname'])(*arg)
		if rv == None:
			# syscalls like os.mkdir, os.rmdir, os.unlink, os.chmod, os.close...
			# return None on success and raise an exception in case of error.
			return (0, 0)
		elif type(rv) == bool:
			# syscalls like os.access return True or False. Since True means
			# success, and for UNIX syscalls succes is 0, we must negate the
			# value (True is represented as 1 and False as 0).
			return (not rv, 0)
		else:
			# syscalls like os.open return an integer (e.g. a file descriptor)
			# in case of success.
			return (rv, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysOpen = sysRmdir = sysUnlink = sysAccess = sysMkdir = sysChmod = \
		sysClose = sysLink = sysSymlink = sysLseek = sysUtime = sysUtimes = \
		sysGeneric

# The following system calls can't be managed directly by a generic function
# because they must return some complex structure, so they have their specific
# functions.

# manages stat64, lstat64, fstat64
# As the original C system call provides more than one parameter (i.e. it
# includes the buffer where the result must be stored), we must call the
# Python function passing only the first parameter (arg[0]).
def sysStats(*arg, **kw):
	print "Calling system call", kw['cname'], "with parameters", arg
	try:
		os.stat_float_times(False)
		return (0, 0, getattr(os, kw['cname'].rstrip('64'))(arg[0]))
	except OSError, (errno, strerror):
		return (-1, errno)

sysStat64 = sysLstat64 = sysFstat64 = sysStats

def sysStatfs64(path, **kw):
	print "Calling system call", kw['cname'], "with parameters", path
	try:
		return (0, 0, os.statvfs(path))
	except OSError, (errno, strerror):
		return (-1, errno)

def sysReadlink(path, bufsiz, **kw):
	print "Calling system call", kw['cname'], "with parameters", path, bufsiz
	try:
		tmplink = os.readlink(path)
		return (min(bufsiz, len(tmplink)), 0, tmplink[0:bufsiz])
	except OSError, (errno, strerror):
		return (-1, errno)

def sysRead(fd, count, **kw):
	print "Calling system call", kw['cname'], "with parameters", fd, count
	try:
		rv = os.read(fd, count);
		return (len(rv), 0, rv)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysWrite(fd, buf, count, **kw):
	print "Calling system call", kw['cname'], "with parameters", fd, buf, count
	try:
		return (os.write(fd, buf), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

