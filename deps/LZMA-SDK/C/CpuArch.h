/* CpuArch.h -- CPU specific code
2021-04-25 : Igor Pavlov : Public domain */

#ifndef __CPU_ARCH_H
#define __CPU_ARCH_H

#include "7zTypes.h"

EXTERN_C_BEGIN

/*
MY_CPU_LE means that CPU is LITTLE ENDIAN.
MY_CPU_BE means that CPU is BIG ENDIAN.
If MY_CPU_LE and MY_CPU_BE are not defined, we don't know about ENDIANNESS of platform.

MY_CPU_LE_UNALIGN means that CPU is LITTLE ENDIAN and CPU supports unaligned memory accesses.

MY_CPU_64BIT means that processor can work with 64-bit registers.
  MY_CPU_64BIT can be used to select fast code branch
  MY_CPU_64BIT doesn't mean that (sizeof(void *) == 8)
*/

#if  defined(_M_X64) \
  || defined(_M_AMD64) \
  || defined(__x86_64__) \
  || defined(__AMD64__) \
  || defined(__amd64__)
  #define MY_CPU_AMD64
  #ifdef __ILP32__
    #define MY_CPU_NAME "x32"
    #define MY_CPU_SIZEOF_POINTER 4
  #else
    #define MY_CPU_NAME "x64"
    #define MY_CPU_SIZEOF_POINTER 8
  #endif
  #define MY_CPU_64BIT
#endif


#if  defined(_M_IX86) \
  || defined(__i386__)
  #define MY_CPU_X86
  #define MY_CPU_NAME "x86"
  /* #define MY_CPU_32BIT */
  #define MY_CPU_SIZEOF_POINTER 4
#endif


#if  defined(_M_ARM64) \
  || defined(__AARCH64EL__) \
  || defined(__AARCH64EB__) \
  || defined(__aarch64__)
  #define MY_CPU_ARM64
  #define MY_CPU_NAME "arm64"
  #define MY_CPU_64BIT
#endif


#if  defined(_M_ARM) \
  || defined(_M_ARM_NT) \
  || defined(_M_ARMT) \
  || defined(__arm__) \
  || defined(__thumb__) \
  || defined(__ARMEL__) \
  || defined(__ARMEB__) \
  || defined(__THUMBEL__) \
  || defined(__THUMBEB__)
  #define MY_CPU_ARM

  #if defined(__thumb__) || defined(__THUMBEL__) || defined(_M_ARMT)
    #define MY_CPU_NAME "armt"
  #else
    #define MY_CPU_NAME "arm"
  #endif
  /* #define MY_CPU_32BIT */
  #define MY_CPU_SIZEOF_POINTER 4
#endif


#if  defined(_M_IA64) \
  || defined(__ia64__)
  #define MY_CPU_IA64
  #define MY_CPU_NAME "ia64"
  #define MY_CPU_64BIT
#endif


#if  defined(__mips64) \
  || defined(__mips64__) \
  || (defined(__mips) && (__mips == 64 || __mips == 4 || __mips == 3))
  #define MY_CPU_NAME "mips64"
  #define MY_CPU_64BIT
#elif defined(__mips__)
  #define MY_CPU_NAME "mips"
  /* #define MY_CPU_32BIT */
#endif


#if  defined(__ppc64__) \
  || defined(__powerpc64__) \
  || defined(__ppc__) \
  || defined(__powerpc__) \
  || defined(__PPC__) \
  || defined(_POWER)

#if  defined(__ppc64__) \
  || defined(__powerpc64__) \
  || defined(_LP64) \
  || defined(__64BIT__)
  #ifdef __ILP32__
    #define MY_CPU_NAME "ppc64-32"
    #define MY_CPU_SIZEOF_POINTER 4
  #else
    #define MY_CPU_NAME "ppc64"
    #define MY_CPU_SIZEOF_POINTER 8
  #endif
  #define MY_CPU_64BIT
#else
  #define MY_CPU_NAME "ppc"
  #define MY_CPU_SIZEOF_POINTER 4
  /* #define MY_CPU_32BIT */
#endif
#endif


#if  defined(__sparc64__)
  #define MY_CPU_NAME "sparc64"
  #define MY_CPU_64BIT
#elif defined(__sparc__)
  #define MY_CPU_NAME "sparc"
  /* #define MY_CPU_32BIT */
#endif


#if defined(MY_CPU_X86) || defined(MY_CPU_AMD64)
#define MY_CPU_X86_OR_AMD64
#endif

#if defined(MY_CPU_ARM) || defined(MY_CPU_ARM64)
#define MY_CPU_ARM_OR_ARM64
#endif


#ifdef _WIN32

  #ifdef MY_CPU_ARM
  #define MY_CPU_ARM_LE
  #endif

  #ifdef MY_CPU_ARM64
  #define MY_CPU_ARM64_LE
  #endif

  #ifdef _M_IA64
  #define MY_CPU_IA64_LE
  #endif

#endif


#if defined(MY_CPU_X86_OR_AMD64) \
    || defined(MY_CPU_ARM_LE) \
    || defined(MY_CPU_ARM64_LE) \
    || defined(MY_CPU_IA64_LE) \
    || defined(__LITTLE_ENDIAN__) \
    || defined(__ARMEL__) \
    || defined(__THUMBEL__) \
    || defined(__AARCH64EL__) \
    || defined(__MIPSEL__) \
    || defined(__MIPSEL) \
    || defined(_MIPSEL) \
    || defined(__BFIN__) \
    || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
  #define MY_CPU_LE
#endif

#if defined(__BIG_ENDIAN__) \
    || defined(__ARMEB__) \
    || defined(__THUMBEB__) \
    || defined(__AARCH64EB__) \
    || defined(__MIPSEB__) \
    || defined(__MIPSEB) \
    || defined(_MIPSEB) \
    || defined(__m68k__) \
    || defined(__s390__) \
    || defined(__s390x__) \
    || defined(__zarch__) \
    || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
  #define MY_CPU_BE
#endif


#if defined(MY_CPU_LE) && defined(MY_CPU_BE)
  #error Stop_Compiling_Bad_Endian
#endif


#if defined(MY_CPU_32BIT) && defined(MY_CPU_64BIT)
  #error Stop_Compiling_Bad_32_64_BIT
#endif

#ifdef __SIZEOF_POINTER__
  #ifdef MY_CPU_SIZEOF_POINTER
    #if MY_CPU_SIZEOF_POINTER != __SIZEOF_POINTER__
      #error Stop_Compiling_Bad_MY_CPU_PTR_SIZE
    #endif
  #else
    #define MY_CPU_SIZEOF_POINTER  __SIZEOF_POINTER__
  #endif
#endif

#if defined(MY_CPU_SIZEOF_POINTER) && (MY_CPU_SIZEOF_POINTER == 4)
#if defined (_LP64)
      #error Stop_Compiling_Bad_MY_CPU_PTR_SIZE
#endif
#endif

#ifdef _MSC_VER
  #if _MSC_VER >= 1300
    #define MY_CPU_pragma_pack_push_1   __pragma(pack(push, 1))
    #define MY_CPU_pragma_pop           __pragma(pack(pop))
  #else
    #define MY_CPU_pragma_pack_push_1
    #define MY_CPU_pragma_pop
  #endif
#else
  #ifdef __xlC__
    // for XLC compiler:
    #define MY_CPU_pragma_pack_push_1   _Pragma("pack(1)")
    #define MY_CPU_pragma_pop           _Pragma("pack()")
  #else
    #define MY_CPU_pragma_pack_push_1   _Pragma("pack(push, 1)")
    #define MY_CPU_pragma_pop           _Pragma("pack(pop)")
  #endif
#endif


#ifndef MY_CPU_NAME
  #ifdef MY_CPU_LE
    #define MY_CPU_NAME "LE"
  #elif defined(MY_CPU_BE)
    #define MY_CPU_NAME "BE"
  #else
    /*
    #define MY_CPU_NAME ""
    */
  #endif
#endif





#ifdef MY_CPU_LE
  #if defined(MY_CPU_X86_OR_AMD64) \
      || defined(MY_CPU_ARM64) \
      || defined(__ARM_FEATURE_UNALIGNED)
    #define MY_CPU_LE_UNALIGN
  #endif
#endif


#ifdef MY_CPU_LE_UNALIGN

#define GetUi16(p) (*(const UInt16 *)(const void *)(p))
#define GetUi32(p) (*(const UInt32 *)(const void *)(p))
#define GetUi64(p) (*(const UInt64 *)(const void *)(p))

#define SetUi16(p, v) { *(UInt16 *)(void *)(p) = (v); }
#define SetUi32(p, v) { *(UInt32 *)(void *)(p) = (v); }
#define SetUi64(p, v) { *(UInt64 *)(void *)(p) = (v); }

#else

#define GetUi16(p) ( (UInt16) ( \
             ((const Byte *)(p))[0] | \
    ((UInt16)((const Byte *)(p))[1] << 8) ))

#define GetUi32(p) ( \
             ((const Byte *)(p))[0]        | \
    ((UInt32)((const Byte *)(p))[1] <<  8) | \
    ((UInt32)((const Byte *)(p))[2] << 16) | \
    ((UInt32)((const Byte *)(p))[3] << 24))

#define GetUi64(p) (GetUi32(p) | ((UInt64)GetUi32(((const Byte *)(p)) + 4) << 32))

#define SetUi16(p, v) { Byte *_ppp_ = (Byte *)(p); UInt32 _vvv_ = (v); \
    _ppp_[0] = (Byte)_vvv_; \
    _ppp_[1] = (Byte)(_vvv_ >> 8); }

#define SetUi32(p, v) { Byte *_ppp_ = (Byte *)(p); UInt32 _vvv_ = (v); \
    _ppp_[0] = (Byte)_vvv_; \
    _ppp_[1] = (Byte)(_vvv_ >> 8); \
    _ppp_[2] = (Byte)(_vvv_ >> 16); \
    _ppp_[3] = (Byte)(_vvv_ >> 24); }

#define SetUi64(p, v) { Byte *_ppp2_ = (Byte *)(p); UInt64 _vvv2_ = (v); \
    SetUi32(_ppp2_    , (UInt32)_vvv2_); \
    SetUi32(_ppp2_ + 4, (UInt32)(_vvv2_ >> 32)); }

#endif

#ifdef __has_builtin
  #define MY__has_builtin(x) __has_builtin(x)
#else
  #define MY__has_builtin(x) 0
#endif

#if defined(MY_CPU_LE_UNALIGN) && /* defined(_WIN64) && */ defined(_MSC_VER) && (_MSC_VER >= 1300)

/* Note: we use bswap instruction, that is unsupported in 386 cpu */

#include <stdlib.h>

#pragma intrinsic(_byteswap_ushort)
#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(_byteswap_uint64)

/* #define GetBe16(p) _byteswap_ushort(*(const UInt16 *)(const Byte *)(p)) */
#define GetBe32(p) _byteswap_ulong (*(const UInt32 *)(const void *)(p))
#define GetBe64(p) _byteswap_uint64(*(const UInt64 *)(const void *)(p))

#define SetBe32(p, v) (*(UInt32 *)(void *)(p)) = _byteswap_ulong(v)

#elif defined(MY_CPU_LE_UNALIGN) && ( \
       (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))) \
    || (defined(__clang__) && MY__has_builtin(__builtin_bswap16)) )

/* #define GetBe16(p) __builtin_bswap16(*(const UInt16 *)(const void *)(p)) */
#define GetBe32(p) __builtin_bswap32(*(const UInt32 *)(const void *)(p))
#define GetBe64(p) __builtin_bswap64(*(const UInt64 *)(const void *)(p))

#define SetBe32(p, v) (*(UInt32 *)(void *)(p)) = __builtin_bswap32(v)

#else

#define GetBe32(p) ( \
    ((UInt32)((const Byte *)(p))[0] << 24) | \
    ((UInt32)((const Byte *)(p))[1] << 16) | \
    ((UInt32)((const Byte *)(p))[2] <<  8) | \
             ((const Byte *)(p))[3] )

#define GetBe64(p) (((UInt64)GetBe32(p) << 32) | GetBe32(((const Byte *)(p)) + 4))

#define SetBe32(p, v) { Byte *_ppp_ = (Byte *)(p); UInt32 _vvv_ = (v); \
    _ppp_[0] = (Byte)(_vvv_ >> 24); \
    _ppp_[1] = (Byte)(_vvv_ >> 16); \
    _ppp_[2] = (Byte)(_vvv_ >> 8); \
    _ppp_[3] = (Byte)_vvv_; }

#endif


#ifndef GetBe16

#define GetBe16(p) ( (UInt16) ( \
    ((UInt16)((const Byte *)(p))[0] << 8) | \
             ((const Byte *)(p))[1] ))

#endif



#ifdef MY_CPU_X86_OR_AMD64

typedef struct
{
  UInt32 maxFunc;
  UInt32 vendor[3];
  UInt32 ver;
  UInt32 b;
  UInt32 c;
  UInt32 d;
} Cx86cpuid;

enum
{
  CPU_FIRM_INTEL,
  CPU_FIRM_AMD,
  CPU_FIRM_VIA
};

void MyCPUID(UInt32 function, UInt32 *a, UInt32 *b, UInt32 *c, UInt32 *d);

BoolInt x86cpuid_CheckAndRead(Cx86cpuid *p);
int x86cpuid_GetFirm(const Cx86cpuid *p);

#define x86cpuid_GetFamily(ver) (((ver >> 16) & 0xFF0) | ((ver >> 8) & 0xF))
#define x86cpuid_GetModel(ver)  (((ver >> 12) &  0xF0) | ((ver >> 4) & 0xF))
#define x86cpuid_GetStepping(ver) (ver & 0xF)

BoolInt CPU_Is_InOrder(void);

BoolInt CPU_IsSupported_AES(void);
BoolInt CPU_IsSupported_VAES_AVX2(void);
BoolInt CPU_IsSupported_SSSE3(void);
BoolInt CPU_IsSupported_SSE41(void);
BoolInt CPU_IsSupported_SHA(void);
BoolInt CPU_IsSupported_PageGB(void);

#elif defined(MY_CPU_ARM_OR_ARM64)

BoolInt CPU_IsSupported_CRC32(void);

#if defined(_WIN32)
BoolInt CPU_IsSupported_CRYPTO(void);
#define CPU_IsSupported_SHA1  CPU_IsSupported_CRYPTO
#define CPU_IsSupported_SHA2  CPU_IsSupported_CRYPTO
#define CPU_IsSupported_AES   CPU_IsSupported_CRYPTO
#else
BoolInt CPU_IsSupported_SHA1(void);
BoolInt CPU_IsSupported_SHA2(void);
BoolInt CPU_IsSupported_AES(void);
#endif

#endif

#if defined(__APPLE__)
int My_sysctlbyname_Get(const char *name, void *buf, size_t *bufSize);
int My_sysctlbyname_Get_UInt32(const char *name, UInt32 *val);
#endif

EXTERN_C_END

#endif
