def modCtl(cls, cmd, cmdArgs):
	print "class:", cls, "command:", cmd, "args:", cmdArgs
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

