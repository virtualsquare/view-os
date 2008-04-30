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
import umpyew

# This list can contain zero or more of the following:
# 'proc', 'module', 'mount'.
modCtlHistorySet = ['proc'];

# If you have any initalization, put it here.
def modInit():
	print "Init!"
#	global ts
#	ts = umpyew.tstTimestamp()

# The same for finalization.
def modFini():
	print "Fini!"
	pass

def modCtl(cls, cmd, cmdArgs):
	print "class:", cls, "command:", cmd, "args:", cmdArgs
	# Just an example
	if cls == 'proc':
		if cmd == 'add':
			print "New process with id %d" % cmdArgs[0]
		elif cmd == 'rem':
			print "Process with id %d removed" % cmdArgs[0]
	return 0

def modCheckFun(*arg, **kw):
	if kw.has_key('path'):
		print "path:", kw['path']
	elif kw.has_key('socket'):
		print "socket:", kw['socket']
	elif kw.has_key('fstype'):
		print "fstype:", kw['fstype']
	elif kw.has_key('sc'):
		print "sc:", kw['sc']
	elif kw.has_key('binfmt'):
		print "binfmt:", kw['binfmt']
	return 0 # Or an epoch, if needed

# The return value of the system call management functions must be a tuple
# with no less than 2 items. The minimal return value is composed by (retval,
# errno). Additional items can be inserted for returning additional data (as
# in stat or readlink syscalls).
def sysOpen(path, flags, mode, **kw):
	print "opening %s with flags %d and mode %d" % (path, flags, mode)
	try:
		return (os.open(path, flags, mode), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysClose(fd, **kw):
	print "closing fd %d" % fd
	try:
		os.close(fd)
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysString(path, **kw):
	print "calling %s('%s')" % (kw['cname'], path)
	try:
		return (getattr(os, kw['cname'])(path), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStringInt(path, mode, **kw):
	print "calling %s('%s', %d)" % (cname, path, mode)
	try:
		return (getattr(os, kw[cname])(path, mode), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStringString(oldpath, newpath, **kw):
	print "calling %s('%s', '%s')" % (cname, oldpath, newpath)
	try:
		return (getattr(os, kw['cname'])(oldpath, newpath), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStats(param="path", **kw):
	print "calling %s" % (kw['cname'])
	try:
		os.stat_float_times(False)
		statinfo = getattr(os, kw['cname'].rstrip('64'))(kw[param])
		buf = {}
		for field in filter(lambda s:s.startswith('st_'), dir(statinfo)):
			buf[field] = getattr(statinfo, field)
		return (0, 0, buf)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysFstat64(**kw):
	return sysStats(param="fd", **kw)

def sysStatfs64(**kw):
	print "calling statfs64('%s')" % path
	try:
		statinfo = os.statvfs(path)
		buf = {}
		for field in filter(lambda s:s.startswith('f_') and not s in ['f_frsize', 'f_favail', 'f_flag', 'f_namemax'], dir(statinfo)):
			buf[field] = getattr(statinfo, field)
		buf['f_namelen'] = statinfo.f_namemax
		return (0, 0, buf)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysReadlink(path, bufsiz, **kw):
	print "calling readlink('%s')" % path
	try:
		tmplink = os.readlink(path)
		return (min(bufsiz, len(tmplink)), 0, tmplink[0:bufsiz])
	except OSError, (errno, strerror):
		return (-1, errno)

def sysLseek(fd, offset, whence, **kw):
	print "calling lseek(%d, %d, %d)" % (fd, offset, whence)
	try:
		return (os.lseek(fd, offset, whence), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysUtimes(path, atime, mtime, **kw):
	print "calling utimes('%s', (%d, %d), (%d, %d))" % (path, atime[0],
			atime[1], mtime[0], mtime[1])
	try:
		os.utime(path, (atime[0] + atime[1]/1000000.0, mtime[0] + mtime[1]/1000000.0))
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysRead(fd, count, **kw):
	print "calling read(%d, %d)" % (fd, count)
	try:
		rv = os.read(fd, count);
		return (len(rv), 0, rv)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysWrite(fd, buf, count, **kw):
	print "calling write(%d, ..., %d)" % (fd, count)
	try:
		return (os.write(fd, buf), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysRmdir = sysUnlink = sysString
sysAccess = sysMkdir = sysChmod = sysStringInt
sysLink = sysSymlink = sysStringString
sysStat64 = sysLstat64 = sysStats
sysUtime = sysUtimes

