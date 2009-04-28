ARCH = x86
EXT = _32
KERNELDIR = "/usr/src/experimental/linux-source-2.6.29-utrace"
ARCHUNISTD = $(KERNELDIR)/arch/$(ARCH)/include/asm/unistd$(EXT).h

arch_fdsyslist: arch_fdsyslist.o

arch_fdsyslist.o: arch_fdsyslist.c fdsyslist.h arch_unistd.h

arch_unistd.h: 
	ln -s $(ARCHUNISTD) arch_unistd.h

fdsyslist.h:	fdsyslist
	awk 'BEGIN {printf "int fdsyslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' fdsyslist > fdsyslist.h

clean:
	rm -f *.o arch_fdsyslist fdsyslist.h core arch_unistd.h
