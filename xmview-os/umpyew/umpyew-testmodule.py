
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
		print "path:", kw['path']
	elif kw.has_key('socket'):
		print "socket:", kw['socket']
	elif kw.has_key('fstype'):
		print "fstype:", kw['fstype']
	elif kw.has_key('sc'):
		print "sc:", kw['sc']
	elif kw.has_key('binfmt'):
		print "binfmt:", kw['binfmt']
	return 0

