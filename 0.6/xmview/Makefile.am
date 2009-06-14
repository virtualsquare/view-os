DEBUGLEVEL = 10

PCB_MODULES = \
	pcb.00.capture.h \
	pcb.00.mainpoll.h \
	pcb.01.sctab.h \
	pcb.02.umproc.h \
	pcb.03.mmap.h \
	pcb.04.select.h

COMMON_SOURCES = \
	canonicalize.c canonicalize.h \
	capture.h \
	capture_nested.c capture_nested.h \
	defs.h \
	gdebug.c \
	mainpoll.c mainpoll.h \
	modutils.c modutils.h \
	pcb.c pcb.h \
	scmap.c scmap.h \
	sctab.c sctab.h \
	siglist.h \
	services.c services.h \
	treepoch.c treepoch.h \
	uid16to32.h \
	um_basicio.c \
	um_exec.c \
	um_ioctl.c \
	um_misc.c \
	um_mmap.c \
	um_plusio.c \
	um_select.c um_select.h \
	um_services.c um_services.h \
	um_signal.c \
	um_socket.c \
	um_time.c \
	um_uname.c \
	um_wdm.c \
	umproc.c umproc.h \
	utils.h \
	loginshell.c loginshell.h \
	kmview.h
# kmview.h must be removed, it will be part of the dev package of the
# kmview.ko kernel module

bin_PROGRAMS = kmview umview

kmview_SOURCES = \
	$(COMMON_SOURCES) \
	capture_km.c capture_km.h \
	defs_i386_km.h defs_ppc_km.h defs_x86_64_km.h \
	kmview.c kmview-main.h

nodist_kmview_SOURCES = \
	pcb-all.h

umview_SOURCES = \
	$(COMMON_SOURCES) \
	capture_um.c capture_um.h \
	defs_i386_um.h defs_ppc_um.h defs_x86_64_um.h \
	ptrace2.h \
	ptrace_multi_test.c ptrace_multi_test.h \
	umview.c umview.h \
	utils_um.c

nodist_umview_SOURCES = \
	pcb-all.h

EXTRA_DIST = $(PCB_MODULES)

kmview_LDADD = -ldl -lpthread
umview_LDADD = -ldl -lpthread

BUILT_SOURCES = pcb-all.h
CLEANFILES = pcb-all.h

libexec_PROGRAMS = umbinwrap
umbinwrap_SOURCES = \
	umbinwrap.c

dist_man1_MANS = kmview.1 umview.1 
dist_man2_MANS = msocket.2viewos
dist_man5_MANS = viewospasswd.5

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
kmview_CPPFLAGS = $(CPPFULLFLAGS) -D_VIEWOS_KM
umview_CPPFLAGS = $(CPPFULLFLAGS) -D_VIEWOS_UM

pcb-all.h: $(PCB_MODULES)
	echo "/* DO NOT EDIT. File Automagically generated */" > pcb-all.h
	cat $(PCB_MODULES) >> pcb-all.h

#ifeq ($(PIVOTING),true)
#
#syscall_code.c syscall_code.h: compile_code.sh
#	./compile_code.sh syscall_code.h syscall_code.c
#
#endif

