DEBUGLEVEL=3
prefix = /usr/local
bindir = ${prefix}/bin
libdir = ${prefix}/lib
mandir = ${prefix}/man
includedir = ${prefix}/include

release = false

export bindir libdir mandir includedir DEBUGLEVEL

ifeq ($(release),true)
RELEASE_FLAGS="RELEASE=true"
else
RELEASE_FLAGS=
endif

all:
	make -C include $(RELEASE_FLAGS)
	make -C gdebug $(RELEASE_FLAGS)
	make -C um-viewos $(RELEASE_FLAGS)
	make -C um_lib  $(RELEASE_FLAGS)
	make -C um_cmd  $(RELEASE_FLAGS)
	make -C um_testmodule  $(RELEASE_FLAGS)
	make -C um_viewfs  $(RELEASE_FLAGS)
	make -C umfuse $(RELEASE_FLAGS)
	make -C umdev $(RELEASE_FLAGS)
	make -C umdev_testmodules $(RELEASE_FLAGS)
	make -C umbinfmt $(RELEASE_FLAGS)
	make -C doc $(RELEASE_FLAGS)
	make -C um_lwip $(RELEASE_FLAGS)

clean:
	make -C include clean $(RELEASE_FLAGS)
	make -C gdebug clean $(RELEASE_FLAGS)
	make -C um-viewos clean $(RELEASE_FLAGS)
	make -C um_lib clean $(RELEASE_FLAGS)
	make -C um_cmd clean $(RELEASE_FLAGS)
	make -C um_testmodule clean $(RELEASE_FLAGS)
	make -C um_viewfs clean $(RELEASE_FLAGS)
	make -C umfuse clean $(RELEASE_FLAGS)
	make -C umdev clean $(RELEASE_FLAGS)
	make -C umdev_testmodules clean $(RELEASE_FLAGS)
	make -C umbinfmt clean $(RELEASE_FLAGS)
	make -C doc clean $(RELEASE_FLAGS)
	make -C um_lwip clean $(RELEASE_FLAGS)
	rm -f ctags cscope.out

distclean:
	make -C include distclean $(RELEASE_FLAGS)
	make -C gdebug distclean $(RELEASE_FLAGS)
	make -C um-viewos distclean $(RELEASE_FLAGS)
	make -C um_lib distclean $(RELEASE_FLAGS)
	make -C um_cmd distclean $(RELEASE_FLAGS)
	make -C um_testmodule distclean $(RELEASE_FLAGS)
	make -C um_viewfs distclean $(RELEASE_FLAGS)
	make -C umfuse distclean $(RELEASE_FLAGS)
	make -C umdev distclean $(RELEASE_FLAGS)
	make -C umdev_testmodules distclean $(RELEASE_FLAGS)
	make -C umbinfmt distclean $(RELEASE_FLAGS)
	make -C doc distclean $(RELEASE_FLAGS)
	make -C um_lwip distclean $(RELEASE_FLAGS)

${bindir}:
	mkdir -p ${bindir}

${libdir}:
	mkdir -p ${libdir}
	
${mandir}:
	mkdir -p ${mandir}

${includedir}:
	mkdir -p ${includedir}

tags:
	ctags -R .

cscope:
	cscope -R -b

vim: tags cscope

install: ${bindir} ${libdir} ${mandir}
	make -C include install $(RELEASE_FLAGS)
	make -C gdebug install $(RELEASE_FLAGS)
	make -C um-viewos install $(RELEASE_FLAGS)
	make -C um_lib install $(RELEASE_FLAGS)
	make -C um_cmd install $(RELEASE_FLAGS)
	make -C um_testmodule install $(RELEASE_FLAGS)
	make -C um_viewfs install $(RELEASE_FLAGS)
	make -C umfuse install $(RELEASE_FLAGS)
	make -C umdev install $(RELEASE_FLAGS)
	make -C umdev_testmodules install $(RELEASE_FLAGS)
	make -C umbinfmt install $(RELEASE_FLAGS)
	make -C doc install $(RELEASE_FLAGS)
	make -C um_lwip install $(RELEASE_FLAGS)

.PHONY: install vim tags cscope clean distclean
