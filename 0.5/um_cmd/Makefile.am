dist_man1_MANS = \
	um_add_service.1 \
	um_del_service.1 \
	um_lock_service.1 \
	um_ls_service.1 \
	um_mov_service.1 \
	vuname.1 \
	viewname.1 \
	umshutdown.1 \
	mstack.1

CPPFLAGS = -I../include

bin_PROGRAMS = \
	um_add_service \
	um_del_service \
	um_lock_service \
	um_ls_service \
	um_mov_service \
	vuname \
	viewname \
	umshutdown \
	mstack

debug release: all

LDADD = ../um_lib/libumlib.la

