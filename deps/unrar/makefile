#
# Makefile for UNIX - unrar

# Linux using GCC
CXX=c++
CXXFLAGS=-O2 -Wno-logical-op-parentheses -Wno-switch -Wno-dangling-else
LIBFLAGS=-fPIC
DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
STRIP=strip
AR=ar
LDFLAGS=-pthread
DESTDIR=/usr

# Linux using LCC
#CXX=lcc
#CXXFLAGS=-O2
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# CYGWIN using GCC
#CXX=c++
#CXXFLAGS=-O2
#LIBFLAGS=
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DRAR_SMP
#STRIP=strip
#AR=ar
#LDFLAGS=-pthread
#DESTDIR=/usr

# HP UX using aCC
#CXX=aCC
#CXXFLAGS=-AA +O2 +Onolimit
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# IRIX using GCC
#CXX=g++
#CXXFLAGS=-O2 
#DEFINES=-DBIG_ENDIAN -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_BSD_COMPAT -D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED=1
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# IRIX using MIPSPro (experimental)
#CXX=CC
#CXXFLAGS=-O2 -mips3 -woff 1234,1156,3284 -LANG:std
#DEFINES=-DBIG_ENDIAN -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_BSD_COMPAT -Dint64=int64_t
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# AIX using xlC (IBM VisualAge C++ 5.0)
#CXX=xlC
#CXXFLAGS=-O -qinline -qro -qroconst -qmaxmem=16384 -qcpluscmt
#DEFINES=-D_LARGE_FILES -D_LARGE_FILE_API
#LIBS=-lbsd
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# Solaris using CC
#CXX=CC
#CXXFLAGS=-fast -erroff=wvarhidemem
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
#STRIP=strip
#AR=ar
#DESTDIR=/usr

# Solaris using GCC (optimized for UltraSPARC 1 CPU)
#CXX=g++
#CXXFLAGS=-O3 -mcpu=v9 -mtune=ultrasparc -m32
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
#STRIP=/usr/ccs/bin/strip
#AR=/usr/ccs/bin/ar
#DESTDIR=/usr

# Tru64 5.1B using GCC3
#CXX=g++
#CXXFLAGS=-O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_XOPEN_SOURCE=500
#STRIP=strip
#AR=ar
#LDFLAGS=-rpath /usr/local/gcc/lib
#DESTDIR=/usr

# Tru64 5.1B using DEC C++
#CXX=cxx
#CXXFLAGS=-O4 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Dint64=long
#STRIP=strip
#AR=ar
#LDFLAGS=
#DESTDIR=/usr

# QNX 6.x using GCC
#CXX=g++
#CXXFLAGS=-O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -fexceptions
#STRIP=strip
#AR=ar
#LDFLAGS=-fexceptions
#DESTDIR=/usr

# Cross-compile
# Linux using arm-linux-g++
#CXX=arm-linux-g++
#CXXFLAGS=-O2
#DEFINES=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
#STRIP=arm-linux-strip
#AR=arm-linux-ar
#LDFLAGS=-static
#DESTDIR=/usr

##########################

COMPILE=$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEFINES)
LINK=$(CXX)

WHAT=UNRAR

UNRAR_OBJ=filestr.o recvol.o rs.o scantree.o qopen.o
LIB_OBJ=filestr.o scantree.o dll.o qopen.o

OBJECTS=rar.o strlist.o strfn.o pathfn.o smallfn.o global.o file.o filefn.o filcreat.o \
	archive.o arcread.o unicode.o system.o isnt.o crypt.o crc.o rawread.o encname.o \
	resource.o match.o timefn.o rdwrfn.o consio.o options.o errhnd.o rarvm.o secpassword.o \
	rijndael.o getbits.o sha1.o sha256.o blake2s.o hash.o extinfo.o extract.o volume.o \
  list.o find.o unpack.o headers.o threadpool.o rs16.o cmddata.o ui.o

.cpp.o:
	$(COMPILE) -D$(WHAT) -c $<

all:	unrar

install:	install-unrar

uninstall:	uninstall-unrar

clean:
	@rm -f *.bak *~
	@rm -f $(OBJECTS) $(UNRAR_OBJ) $(LIB_OBJ)
	@rm -f unrar libunrar.*

unrar:	clean $(OBJECTS) $(UNRAR_OBJ)
	@rm -f unrar
	$(LINK) -o unrar $(LDFLAGS) $(OBJECTS) $(UNRAR_OBJ) $(LIBS)	
	$(STRIP) unrar

sfx:	WHAT=SFX_MODULE
sfx:	clean $(OBJECTS)
	@rm -f default.sfx
	$(LINK) -o default.sfx $(LDFLAGS) $(OBJECTS)
	$(STRIP) default.sfx

lib:	WHAT=RARDLL
lib:	CXXFLAGS+=$(LIBFLAGS)
lib:	clean $(OBJECTS) $(LIB_OBJ)
	@rm -f libunrar.*
	$(LINK) -shared -o libunrar.so $(LDFLAGS) $(OBJECTS) $(LIB_OBJ)
	$(AR) rcs libunrar.a $(OBJECTS) $(LIB_OBJ)

install-unrar:
			install -D unrar $(DESTDIR)/bin/unrar

uninstall-unrar:
			rm -f $(DESTDIR)/bin/unrar

install-lib:
		install libunrar.so $(DESTDIR)/lib
		install libunrar.a $(DESTDIR)/lib

uninstall-lib:
		rm -f $(DESTDIR)/lib/libunrar.so
