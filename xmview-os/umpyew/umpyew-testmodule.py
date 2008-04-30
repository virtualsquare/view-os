import os

# This list can contain zero or more of the following:
# 'proc', 'module', 'mount'.
modCtlHistorySet = ['proc'];

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
#		print "path:", kw['path']
		if kw['path'] == '/tmp/passwd':
			return 1
#	elif kw.has_key('socket'):
#		print "socket:", kw['socket']
#	elif kw.has_key('fstype'):
#		print "fstype:", kw['fstype']
#	elif kw.has_key('sc'):
#		print "sc:", kw['sc']
#	elif kw.has_key('binfmt'):
#		print "binfmt:", kw['binfmt']
	return 0

def sysOpen(**kw):
	print "opening %s with flags %d and mode %d" % (kw['path'], kw['flags'], kw['mode'])
	try:
		return (os.open(kw['path'], kw['flags'], kw['mode']), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysClose(**kw):
	print "closing fd %d" % kw['fd']
	try:
		os.close(kw['fd'])
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysString(**kw):
	print "calling %s('%s')" % (kw['cname'], kw['path'])
	try:
		return (getattr(os, kw[cname])(kw['path']), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStringInt(**kw):
	print "calling %s('%s', %d)" % (kw['cname'], kw['path'], kw['mode'])
	try:
		return (getattr(os, kw[cname])(kw['path'], kw['mode']), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStringString(**kw):
	print "calling %s('%s', '%s')" % (kw['cname'], kw['oldpath'], kw['newpath'])
	try:
		return (getattr(os, kw[cname])(kw['oldpath'], kw['newpath']), 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysStats(param="path", **kw):
	print "calling %s" % (kw['cname'])
	try:
		os.stat_float_times(False)
		statinfo = getattr(os, kw['cname'].rstrip('64'))(kw[param])
		for field in filter(lambda s:s.startswith('st_'), dir(statinfo)):
			kw['buf'][field] = getattr(statinfo, field)
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)

def sysFstat64(**kw):
	return sysStats(param="fd", **kw)

def sysStatfs64(**kw):
	print "calling statfs64('%s')" % kw['path']
	try:
		statinfo = os.statvfs(kw['path'])
		for field in filter(lambda s:s.startswith('f_') and not s in ['f_frsize', 'f_favail', 'f_flag', 'f_namemax'], dir(statinfo)):
			kw['buf'][field] = getattr(statinfo, field)
		kw['buf']['f_namelen'] = statinfo.f_namemax
		return (0, 0)
	except OSError, (errno, strerror):
		return (-1, errno)


sysRmdir = sysUnlink = sysString
sysAccess = sysMkdir = sysChmod = sysStringInt
sysLink = sysSymlink = sysStringString
sysStat64 = sysLstat64 = sysStats


sysRead = sysWrite = None
