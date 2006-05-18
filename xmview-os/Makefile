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
	$(MAKE) -C include $(RELEASE_FLAGS)
	$(MAKE) -C gdebug $(RELEASE_FLAGS)
	$(MAKE) -C um-viewos $(RELEASE_FLAGS)
	$(MAKE) -C um_lib  $(RELEASE_FLAGS)
	$(MAKE) -C um_cmd  $(RELEASE_FLAGS)
	$(MAKE) -C um_testmodule  $(RELEASE_FLAGS)
	$(MAKE) -C um_viewfs  $(RELEASE_FLAGS)
	$(MAKE) -C umfuse $(RELEASE_FLAGS)
	$(MAKE) -C umdev $(RELEASE_FLAGS)
	$(MAKE) -C umdev_testmodules $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt $(RELEASE_FLAGS)
	$(MAKE) -C doc $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip $(RELEASE_FLAGS)

release:
	$(MAKE) release=true

clean:
	$(MAKE) -C include clean $(RELEASE_FLAGS)
	$(MAKE) -C gdebug clean $(RELEASE_FLAGS)
	$(MAKE) -C um-viewos clean $(RELEASE_FLAGS)
	$(MAKE) -C um_lib clean $(RELEASE_FLAGS)
	$(MAKE) -C um_cmd clean $(RELEASE_FLAGS)
	$(MAKE) -C um_testmodule clean $(RELEASE_FLAGS)
	$(MAKE) -C um_viewfs clean $(RELEASE_FLAGS)
	$(MAKE) -C umfuse clean $(RELEASE_FLAGS)
	$(MAKE) -C umdev clean $(RELEASE_FLAGS)
	$(MAKE) -C umdev_testmodules clean $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt clean $(RELEASE_FLAGS)
	$(MAKE) -C doc clean $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip clean $(RELEASE_FLAGS)
	rm -f ctags cscope.out

distclean:
	$(MAKE) -C include distclean $(RELEASE_FLAGS)
	$(MAKE) -C gdebug distclean $(RELEASE_FLAGS)
	$(MAKE) -C um-viewos distclean $(RELEASE_FLAGS)
	$(MAKE) -C um_lib distclean $(RELEASE_FLAGS)
	$(MAKE) -C um_cmd distclean $(RELEASE_FLAGS)
	$(MAKE) -C um_testmodule distclean $(RELEASE_FLAGS)
	$(MAKE) -C um_viewfs distclean $(RELEASE_FLAGS)
	$(MAKE) -C umfuse distclean $(RELEASE_FLAGS)
	$(MAKE) -C umdev distclean $(RELEASE_FLAGS)
	$(MAKE) -C umdev_testmodules distclean $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt distclean $(RELEASE_FLAGS)
	$(MAKE) -C doc distclean $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip distclean $(RELEASE_FLAGS)

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
	$(MAKE) -C include install $(RELEASE_FLAGS)
	$(MAKE) -C gdebug install $(RELEASE_FLAGS)
	$(MAKE) -C um-viewos install $(RELEASE_FLAGS)
	$(MAKE) -C um_lib install $(RELEASE_FLAGS)
	$(MAKE) -C um_cmd install $(RELEASE_FLAGS)
	$(MAKE) -C um_testmodule install $(RELEASE_FLAGS)
	$(MAKE) -C um_viewfs install $(RELEASE_FLAGS)
	$(MAKE) -C umfuse install $(RELEASE_FLAGS)
	$(MAKE) -C umdev install $(RELEASE_FLAGS)
	$(MAKE) -C umdev_testmodules install $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt install $(RELEASE_FLAGS)
	$(MAKE) -C doc install $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip install $(RELEASE_FLAGS)

.PHONY: install vim tags cscope clean distclean
