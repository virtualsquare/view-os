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

def kw2tuple(kw):
	return tuple([item[1] for item in kw.items() if item[0] not in ['cname', 'pyname']])

def sysGenericPath(path, **kw):
	try:
		print "calling", getattr(os, kw['cname'])
		return (getattr(os, kw['cname'])(unwrap(path), **kw), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

sysOpen = sysGenericPath

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
	print "calling %s('%s', %d)" % (kw['cname'], path, mode)
	try:
		return (getattr(os, kw['cname'])(path, mode), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStringString(oldpath, newpath, **kw):
	print "calling %s('%s', '%s')" % (kw['cname'], oldpath, newpath)
	try:
		return (getattr(os, kw['cname'])(oldpath, newpath), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStats(param="path", **kw):
	print "calling %s" % (kw['cname'])
	try:
		os.stat_float_times(False)
		statinfo = getattr(os, kw['cname'].rstrip('64'))(unwrap(kw[param]))
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

