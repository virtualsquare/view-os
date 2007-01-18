DEBUGLEVEL = 3

PCB_MODULES = \
	pcb.00.capture.h \
	pcb.00.mainpoll.h \
	pcb.01.sctab.h \
	pcb.02.umproc.h \
	pcb.03.mmap.h \
	pcb.04.select.h

bin_PROGRAMS = umview
umview_SOURCES = \
	canonicalize.c canonicalize.h \
	capture_nested.c capture_nested.h \
	capture_sc.c capture_sc.h \
	defs.h defs_i386.h defs_ppc.h defs_x86_64.h \
	gdebug.c \
	mainpoll.c mainpoll.h \
	modutils.c modutils.h \
	pcb.c pcb.h \
	ptrace2.h \
	ptrace_multi_test.c ptrace_multi_test.h \
	scmap.c scmap.h \
	sctab.c sctab.h \
	services.c services.h \
	treepoch.c treepoch.h \
	uid16to32.h \
	um_basicio.c \
	um_exec.c \
	um_ioctl.c \
	um_mmap.c \
	um_plusio.c \
	umproc.c umproc.h \
	um_select.c um_select.h \
	um_services.c um_services.h \
	um_signal.c \
	um_socket.c \
	um_time.c \
	um_uname.c \
	umview.c umview.h \
	um_wdm.c \
	utils.c utils.h
nodist_umview_SOURCES = \
	pcb-all.h

EXTRA_DIST = $(PCB_MODULES)

umview_LDADD = -ldl -lpthread

BUILT_SOURCES = pcb-all.h
CLEANFILES = pcb-all.h

libexec_PROGRAMS = umbinwrap
umbinwrap_SOURCES = \
	umbinwrap.c

dist_man1_MANS = umview.1

CBASEFLAGS =
CDEBUGFLAGS = -g3 -ggdb3

CPPBASEFLAGS = -Wall -I../include -D_GNU_SOURCE -DLIBEXECDIR=\"$(libexecdir)\" -DMODULES_DIR=\"$(pkglibdir)/modules\" -D_UM_MMAP -D_USE_PSELECT
CPPDEBUGFLAGS = -DGDEBUG_ENABLED -DGDEBUG_LEVEL=$(DEBUGLEVEL)

if ENABLE_DEBUG
CFULLFLAGS = $(CBASEFLAGS) $(CDEBUGFLAGS)
CPPFULLFLAGS = $(CPPBASEFLAGS) $(CPPDEBUGFLAGS)

release: clean
	$(MAKE) CFULLFLAGS='$(CBASEFLAGS)' CPPFULLFLAGS='$(CPPBASEFLAGS)'

debug: all
else
CFULLFLAGS = $(CBASEFLAGS)
CPPFULLFLAGS = $(CPPBASEFLAGS)

release: all

debug: clean
	$(MAKE) CFULLFLAGS='$(CBASEFLAGS) $(CDEBUGFLAGS)' CPPFULLFLAGS='$(CPPBASEFLAGS) $(CPPDEBUGFLAGS)'
endif

AM_LDFLAGS = -rdynamic
AM_CFLAGS = $(CFULLFLAGS)
AM_CPPFLAGS = $(CPPFULLFLAGS)

pcb-all.h: $(PCB_MODULES)
	echo "/* DO NOT EDIT. File Automagically generated */" > pcb-all.h
	cat $(PCB_MODULES) >> pcb-all.h

#ifeq ($(PIVOTING),true)
#
#syscall_code.c syscall_code.h: compile_code.sh
#	./compile_code.sh syscall_code.h syscall_code.c
#
#endif

