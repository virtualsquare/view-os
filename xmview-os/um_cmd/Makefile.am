dist_man1_MANS = \
	um_add_service.1 \
	um_del_service.1 \
	um_ls_service.1 \
	vuname.1 \
	viewname.1 \
	viewmount.1 \
	viewumount.1 \
	umshutdown.1 \
	mstack.1 \
	viewsu.1 \
	viewsudo.1 \
	um_fsalias.1 \
	um_attach.c

CPPFLAGS = -I../include

bin_PROGRAMS = \
	um_add_service \
	um_del_service \
	um_ls_service \
	vuname \
	viewname \
	viewmount \
	viewumount \
	umshutdown \
	mstack \
	viewsu \
	viewsudo \
	um_fsalias \
	um_attach

um_fsalias_SOURCES=um_alias.c

debug release: all

LDADD = ../um_lib/libumlib.la

