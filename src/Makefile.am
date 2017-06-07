
INSTALL_FOLDER          ?= $(bindir)
LIBRARY_FOLDER          ?= $(libdir)
SHARED_FOLDER           ?= $(datadir)/@PACKAGE@/
DOCUMENT_FOLDER         ?= $(docdir)

AM_LDFLAGS=
AM_CFLAGS=
EXTRA_DIST=

if DEBUG
# use "valgrind --tool=memcheck --leak-check=yes" to check memory leak
DEFS+=-DDEBUG=1
AM_CFLAGS+=-g  -Werror# -Wall

else
AM_CFLAGS+=-O3 -Werror# -Wall
endif

AM_CFLAGS+= \
    -I$(top_srcdir)/src/ \
    -I$(top_srcdir)/OpenCL/ \
    -I$(top_srcdir)/include/ \
    -I$(top_srcdir)/include/lzma_sdk/ \
    -I$(top_builddir)/include/ \
    -I$(top_builddir)/include/lzma_sdk/ \
    $(NULL)

AM_LDFLAGS += \
    -L$(top_builddir)/src/ \
    $(NULL)

DEFS+= \
    `getconf LFS_CFLAGS` \
    `getconf LFS64_CFLAGS` \
    -D_GNU_SOURCE \
    -D_FILE_OFFSET_BITS=64 \
    -DHAVE_MMAP64=1 \
    $(NULL)

libhashcat_la_LDFLAGS=
libhashcat_la_CPPFLAGS=

include_HEADERS = \
    $(top_srcdir)/include/hashcat.h \
    $(NULL)

EXTRA_DIST += libhashcat.pc.in

pkgconfigdir = $(LIBRARY_FOLDER)/pkgconfig
pkgconfig_DATA = libhashcat.pc

#BUILT_SOURCES = $(top_builddir)/src/xmllex.c
#CLEANFILES = $(top_builddir)/src/xmllex.c
#nodist_program_SOURCES = $(top_builddir)/src/xmllex.c
#$(top_builddir)/src/xmllex.c: $(top_srcdir)/src/xmllex.l $(top_srcdir)/src/xmldecl.h
#	$(LEX) -o $@ $(top_srcdir)/src/xmllex.l

lib_LTLIBRARIES=libhashcat.la
libhashcat_la_SOURCES= \
    affinity.c \
    autotune.c \
    benchmark.c \
    bitmap.c \
    bitops.c \
    combinator.c \
    common.c \
    convert.c \
    cpt.c \
    cpu_aes.c \
    cpu_crc32.c \
    cpu_des.c \
    cpu_md4.c \
    cpu_md5.c \
    cpu_sha1.c \
    cpu_sha256.c \
    debugfile.c \
    dictstat.c \
    dispatch.c \
    dynloader.c \
    event.c \
    ext_ADL.c \
    ext_nvapi.c \
    ext_nvml.c \
    ext_OpenCL.c \
    ext_sysfs.c \
    ext_xnvctrl.c \
    ext_lzma.c \
    lzma_sdk/Alloc.c \
    lzma_sdk/Lzma2Dec.c \
    lzma_sdk/LzmaDec.c \
    filehandling.c \
    folder.c \
    hashcat.c \
    hashes.c \
    hlfmt.c \
    hwmon.c \
    induct.c \
    interface.c \
    locking.c \
    logfile.c \
    loopback.c \
    memory.c \
    monitor.c \
    mpsp.c \
    opencl.c \
    outfile_check.c \
    outfile.c \
    pidfile.c \
    potfile.c \
    restore.c \
    rp.c \
    rp_cpu.c \
    rp_kernel_on_cpu.c \
    shared.c \
    status.c \
    stdout.c \
    straight.c \
    terminal.c \
    thread.c \
    timer.c \
    tuningdb.c \
    usage.c \
    user_options.c \
    weak_hash.c \
    wordlist.c \
    $(NULL)

bin_PROGRAMS=hashcat

hashcat_SOURCES= \
    main.c \
    $(NULL)

hashcat_LDADD = -lhashcat -lm $(LIBPSAPI)

COMPTIME = $(shell date +%s)

@MK@GITNUMTMP=$(shell cd "$(top_srcdir)"; echo $$(git describe --tags|sed -r 's|v?(.+)|\1|'|sed 's|-|+|g'); cd - > /dev/null )
#@MK@GITNUMTMP=$(shell cd "$(top_srcdir)"; A=$$(git show | head -n 1 | awk '{print $$2}'); echo $${A:0:7}; cd - > /dev/null )
@MK@ifeq ($(GITNUMTMP),)
@MK@else
VERSION_TAG="${GITNUMTMP}"
@MK@endif

hashcat_CFLAGS = $(AM_CFLAGS) -DCOMPTIME=$(COMPTIME) -DVERSION_TAG=\"$(VERSION_TAG)\" -DINSTALL_FOLDER=\"$(INSTALL_FOLDER)\" -DSHARED_FOLDER=\"$(SHARED_FOLDER)\" -DDOCUMENT_FOLDER=\"$(DOCUMENT_FOLDER)\"
hashcat_LDFLAGS = $(AM_LDFLAGS)
