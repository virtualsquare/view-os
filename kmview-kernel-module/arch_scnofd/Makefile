ARCH = x86
EXT = _64
KERNELDIR = "/usr/src/experimental/linux-2.6.37-utrace-vm"
ARCHUNISTD = $(KERNELDIR)/arch/$(ARCH)/include/asm/unistd$(EXT).h

arch_syslist: arch_syslist.o

arch_syslist.o: arch_syslist.c fdsyslist.h pathsyslist.h arch_unistd.h ../kmview.h

arch_unistd.h: 
	ln -s $(ARCHUNISTD) arch_unistd.h

fdsyslist.h:	fdsyslist
	awk 'BEGIN {printf "int fdsyslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' fdsyslist > fdsyslist.h

pathsyslist.h: path0list path1list path2list path3list atlist selectpolllist
	awk 'BEGIN {printf "int path0syslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' path0list > pathsyslist.h
	awk 'BEGIN {printf "int path1syslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' path1list >> pathsyslist.h
	awk 'BEGIN {printf "int path2syslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' path2list >> pathsyslist.h
	awk 'BEGIN {printf "int path3syslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' path3list >> pathsyslist.h
	awk 'BEGIN {printf "int atsyslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' atlist >> pathsyslist.h
	awk 'BEGIN {printf "int selectpollsyslist[]={\n";} \
{printf "#ifdef %s\n  %s,\n#endif\n",$$1,$$1;} \
END {printf "};\n";}' selectpolllist >> pathsyslist.h

clean:
	rm -f *.o arch_fdsyslist fdsyslist.h core arch_unistd.h
