DEBUGLEVEL=3
prefix = /usr/local
bindir = ${prefix}/bin
libdir = ${prefix}/lib
mandir = ${prefix}/man
includedir = ${prefix}/include

release = true

export bindir libdir mandir includedir DEBUGLEVEL

ifeq ($(release),true)
RELEASE_FLAGS="RELEASE=true"
else
RELEASE_FLAGS="RELEASE=false"
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
	$(MAKE) -C umdevmbr $(RELEASE_FLAGS)
	$(MAKE) -C umdevtap $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt $(RELEASE_FLAGS)
	$(MAKE) -C doc $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip $(RELEASE_FLAGS)

release:
	$(MAKE) release=true

debug:
	$(MAKE) release=false

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
	$(MAKE) -C umdevmbr clean $(RELEASE_FLAGS)
	$(MAKE) -C umdevtap clean $(RELEASE_FLAGS)
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
	$(MAKE) -C umdevmbr distclean $(RELEASE_FLAGS)
	$(MAKE) -C umdevtap distclean $(RELEASE_FLAGS)
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
#	$(MAKE) -C um_viewfs install $(RELEASE_FLAGS)
	$(MAKE) -C umfuse install $(RELEASE_FLAGS)
	$(MAKE) -C umdev install $(RELEASE_FLAGS)
	$(MAKE) -C umdev_testmodules install $(RELEASE_FLAGS)
	$(MAKE) -C umdevmbr install $(RELEASE_FLAGS)
	$(MAKE) -C umdevtap install $(RELEASE_FLAGS)
	$(MAKE) -C umbinfmt install $(RELEASE_FLAGS)
	$(MAKE) -C doc install $(RELEASE_FLAGS)
	$(MAKE) -C um_lwip install $(RELEASE_FLAGS)

.PHONY: install vim tags cscope clean distclean

