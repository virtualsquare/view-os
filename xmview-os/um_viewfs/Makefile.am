include $(top_srcdir)/modules-common.mk

mod_LTLIBRARIES = viewfs0.la modifshide.la
# mod_LTLIBRARIES = modifshide.la

modifshide_la_SOURCES = modifshide.c gd64helper.c
modifshide_la_CFLAGS = $(GLIB20_CFLAGS) -Wall -g -ggdb3
modifshide_la_LIBADD = $(GLIB20_LIBS)

viewfs0_la_SOURCES = viewfs0.c viewfs0args.c
# viewfs_la_CFLAGS = -Wall -g -ggdb3
