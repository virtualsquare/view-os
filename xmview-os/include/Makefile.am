nodist_noinst_HEADERS = syscallnames.h nrsyscalls.h

pkgincludedir = $(includedir)/umview

dist_pkginclude_HEADERS = \
	gdebug.h \
	libummod.h \
	module.h \
	um_lib.h \
	msocket.h \
	ummisc.h \
	umnet.h \
	umdev.h

dist_noinst_SCRIPTS = \
	syscallnames.sh

BUILT_SOURCES = syscallnames.h nrsyscalls.h
CLEANFILES = syscallnames.h nrsyscalls.h 

syscallnames.h: syscallnames.sh
	./syscallnames.sh

nrsyscalls.h: syscallnames.h

debug release: all

