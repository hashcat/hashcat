CFLAGS = $(CFLAGS) -D_7ZIP_PPMD_SUPPPORT

PROG = 7zDec.exe

C_OBJS = \
  $O\7zAlloc.obj \
  $O\7zBuf.obj \
  $O\7zCrc.obj \
  $O\7zCrcOpt.obj \
  $O\7zFile.obj \
  $O\7zDec.obj \
  $O\7zArcIn.obj \
  $O\7zStream.obj \
  $O\Bcj2.obj \
  $O\Bra.obj \
  $O\Bra86.obj \
  $O\BraIA64.obj \
  $O\CpuArch.obj \
  $O\Delta.obj \
  $O\Lzma2Dec.obj \
  $O\LzmaDec.obj \
  $O\Ppmd7.obj \
  $O\Ppmd7Dec.obj \

7Z_OBJS = \
  $O\7zMain.obj \

OBJS = \
  $O\Precomp.obj \
  $(7Z_OBJS) \
  $(C_OBJS) \

!include "../../../CPP/Build.mak"

$(7Z_OBJS): $(*B).c
	$(CCOMPL_USE)
$(C_OBJS): ../../$(*B).c
	$(CCOMPL_USE)
$O\Precomp.obj: Precomp.c
	$(CCOMPL_PCH)
