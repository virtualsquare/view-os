
include $(top_srcdir)/Makefile.common

ALL_INCLUDES = @RLOG_CFLAGS@ @OPENSSL_CFLAGS@
ALL_LDFLAGS = @RLOG_LIBS@ @OPENSSL_LIBS@ -lfuse

INCLUDES = $(all_includes) -I../intl

AM_CXXFLAGS = -DRLOG_COMPONENT="encfs" $(ALL_INCLUDES) 

if BUILD_NLS
# define a C macro LOCALEDIR indicating where catalogs will be installed
localedir = $(datadir)/locale

AM_CXXFLAGS += -DLOCALEDIR=\"$(localedir)\"
ALL_LDFLAGS += @LIBINTL@
endif

lib_LTLIBRARIES = libencfs.la
bin_PROGRAMS = encfs encfsctl umfuseencfs
dist_bin_SCRIPTS = encfssh
noinst_PROGRAMS = test

all-local: encfs-man.html

#encfs_LDADD   = libencfs.la -lfuse
#encfsctl_LDADD = libencfs.la -lfuse
#test_LDADD   = libencfs.la -lfuse
encfs_LDADD   = libencfs.la $(ALL_LDFLAGS)
encfsctl_LDADD = libencfs.la $(ALL_LDFLAGS)
test_LDADD   = libencfs.la $(ALL_LDFLAGS)


# CURRENT : REVISION : AGE
#   +1  :  0  :  +1       => new interface that does not break old one
#   +1  :  0  :   0       => new interface that breaks old one
#       :     :   0       => no new interfaces, but breaks old apps
#       :  +1 :           => internal changes, nothing breaks
#
libencfs_la_LDFLAGS = -version-info 2:0:1
libencfs_la_LIBADD = -lrlog

EXTRASRC = ../intl/autosprintf.cpp
if BUILD_OPENSSL
EXTRASRC += CipherV3.cpp
if BUILD_SSLCIPHER
EXTRASRC += SSL_Cipher.cpp
endif
endif

libencfs_la_SOURCES = \
    Ptr.cpp \
    PtrImpl.cpp \
    OpaqueValue.cpp \
    readpassphrase.cpp \
    base64.cpp \
    Config.cpp \
    ConfigVar.cpp \
    Cipher.cpp \
    LinkedOwner.cpp \
    FileIO.cpp \
    RawFileIO.cpp \
    BlockFileIO.cpp \
    CipherFileIO.cpp \
    MACFileIO.cpp \
    MACFileIOCompat.cpp \
    NameIO.cpp \
    StreamNameIO.cpp \
    BlockNameIO.cpp \
    NullNameIO.cpp \
    Interface.cpp \
    MemoryPool.cpp \
    NullCipher.cpp \
    DirNode.cpp \
    FileNode.cpp \
    FileUtils.cpp \
    ${EXTRASRC}


encfs_SOURCES = \
    encfs.cpp \
    main.cpp


umfuseencfs_SOURCES = \
	encfs.cpp \
	main.cpp

umfuseencfs_LDFLAGS = \
	-shared \
	-nostartfiles
	

test_SOURCES = \
    test.cpp

encfsctl_SOURCES = \
    encfsctl.cpp

noinst_HEADERS = \
    base64.h \
    BlockFileIO.h \
    BlockNameIO.h \
    CipherFileIO.h \
    Cipher.h \
    CipherV3.h \
    Config.h \
    ConfigVar.h \
    DirNode.h \
    encfs.h \
    FileIO.h \
    FileNode.h \
    FileUtils.h \
    Interface.h \
    i18n.h \
    LinkedOwner.h \
    MACFileIOCompat.h \
    MACFileIO.h \
    MemoryPool.h \
    Mutex.h \
    NameIO.h \
    NullCipher.h \
    NullNameIO.h \
    OpaqueValue.h \
    PtrByValueImpl.h \
    Ptr.h \
    PtrImpl.h \
    Range.h \
    RawFileIO.h \
    readpassphrase.h \
    SSL_Cipher.h \
    StreamNameIO.h

man_MANS=encfs.1 encfsctl.1
EXTRA_DIST = encfs.pod encfsctl.pod encfs.1 encfsctl.1 encfs-man.html

if BUILD_MAN
SUFFIXES = .1 .pod
# since we have POD2MAN, we can specify how to rebuild encfs.1 if necessary
.pod.1:
	@POD2MAN@ --section=1 --release=@VERSION@ --center="Encrypted Filesystem" $< $@

CLEANFILES = encfs.1 encfsctl.1
endif

if BUILD_MANHTML
encfs-man.html: encfs.pod
	@POD2HTML@ encfs.pod > $@
endif

