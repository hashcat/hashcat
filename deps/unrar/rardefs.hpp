#ifndef _RAR_DEFS_
#define _RAR_DEFS_

#define  Min(x,y) (((x)<(y)) ? (x):(y))
#define  Max(x,y) (((x)>(y)) ? (x):(y))

// Universal replacement of abs function.
#define  Abs(x) (((x)<0) ? -(x):(x))

#define  ASIZE(x) (sizeof(x)/sizeof(x[0]))

// MAXPASSWORD and MAXPASSWORD_RAR are expected to be multiple of
// CRYPTPROTECTMEMORY_BLOCK_SIZE (16) for CryptProtectMemory in SecPassword.
// We allow a larger MAXPASSWORD to unpack archives with lengthy passwords
// in non-RAR formats in GUI versions. For RAR format we set MAXPASSWORD_RAR
// to 128 for compatibility and because it is enough for AES-256.
#define  MAXPASSWORD       512
#define  MAXPASSWORD_RAR   128

#define  MAXSFXSIZE        0x200000

#define  MAXCMTSIZE        0x40000

#define  DefSFXName        L"default.sfx"
#define  DefSortListName   L"rarfiles.lst"


#ifndef SFX_MODULE
#define USE_QOPEN
#endif

// Produce the value, which is equal or larger than 'v' and aligned to 'a'.
#define ALIGN_VALUE(v,a) (size_t(v) + ( (~size_t(v) + 1) & (a - 1) ) )

#endif
