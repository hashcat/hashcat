MY_STATIC_LINK=1
SLIB = sLZMA.lib
PROG = LZMA.dll
SLIBPATH = $O\$(SLIB)

DEF_FILE = LzmaLib.def
CFLAGS = $(CFLAGS) \

LIB_OBJS = \
  $O\LzmaLibExports.obj \

C_OBJS = \
  $O\Alloc.obj \
  $O\LzFind.obj \
  $O\LzFindMt.obj \
  $O\LzmaDec.obj \
  $O\LzmaEnc.obj \
  $O\LzmaLib.obj \
  $O\Threads.obj \

OBJS = \
  $(LIB_OBJS) \
  $(C_OBJS) \
  $O\resource.res

!include "../../../CPP/Build.mak"

$(SLIBPATH): $O $(OBJS)
	lib -out:$(SLIBPATH) $(OBJS) $(LIBS)

$(LIB_OBJS): $(*B).c
	$(COMPL_O2)
$(C_OBJS): ../../$(*B).c
	$(COMPL_O2)
