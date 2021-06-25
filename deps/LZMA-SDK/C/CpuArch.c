/* CpuArch.c -- CPU specific code
2021-04-28 : Igor Pavlov : Public domain */

#include "Precomp.h"

#include "CpuArch.h"

#ifdef MY_CPU_X86_OR_AMD64

#if (defined(_MSC_VER) && !defined(MY_CPU_AMD64)) || defined(__GNUC__)
#define USE_ASM
#endif

#if !defined(USE_ASM) && _MSC_VER >= 1500
#include <intrin.h>
#endif

#if defined(USE_ASM) && !defined(MY_CPU_AMD64)
static UInt32 CheckFlag(UInt32 flag)
{
  #ifdef _MSC_VER
  __asm pushfd;
  __asm pop EAX;
  __asm mov EDX, EAX;
  __asm xor EAX, flag;
  __asm push EAX;
  __asm popfd;
  __asm pushfd;
  __asm pop EAX;
  __asm xor EAX, EDX;
  __asm push EDX;
  __asm popfd;
  __asm and flag, EAX;
  #else
  __asm__ __volatile__ (
    "pushf\n\t"
    "pop  %%EAX\n\t"
    "movl %%EAX,%%EDX\n\t"
    "xorl %0,%%EAX\n\t"
    "push %%EAX\n\t"
    "popf\n\t"
    "pushf\n\t"
    "pop  %%EAX\n\t"
    "xorl %%EDX,%%EAX\n\t"
    "push %%EDX\n\t"
    "popf\n\t"
    "andl %%EAX, %0\n\t":
    "=c" (flag) : "c" (flag) :
    "%eax", "%edx");
  #endif
  return flag;
}
#define CHECK_CPUID_IS_SUPPORTED if (CheckFlag(1 << 18) == 0 || CheckFlag(1 << 21) == 0) return False;
#else
#define CHECK_CPUID_IS_SUPPORTED
#endif

#ifndef USE_ASM
  #ifdef _MSC_VER
    #if _MSC_VER >= 1600
      #define MY__cpuidex  __cpuidex
    #else

/*
 __cpuid (function == 4) requires subfunction number in ECX.
  MSDN: The __cpuid intrinsic clears the ECX register before calling the cpuid instruction.
   __cpuid() in new MSVC clears ECX.
   __cpuid() in old MSVC (14.00) doesn't clear ECX
 We still can use __cpuid for low (function) values that don't require ECX,
 but __cpuid() in old MSVC will be incorrect for some function values: (function == 4).
 So here we use the hack for old MSVC to send (subFunction) in ECX register to cpuid instruction,
 where ECX value is first parameter for FAST_CALL / NO_INLINE function,
 So the caller of MY__cpuidex_HACK() sets ECX as subFunction, and
 old MSVC for __cpuid() doesn't change ECX and cpuid instruction gets (subFunction) value.
 
 DON'T remove MY_NO_INLINE and MY_FAST_CALL for MY__cpuidex_HACK() !!!
*/

static
MY_NO_INLINE
void MY_FAST_CALL MY__cpuidex_HACK(UInt32 subFunction, int *CPUInfo, UInt32 function)
{
  UNUSED_VAR(subFunction);
  __cpuid(CPUInfo, function);
}

      #define MY__cpuidex(info, func, func2)  MY__cpuidex_HACK(func2, info, func)
      #pragma message("======== MY__cpuidex_HACK WAS USED ========")
    #endif
  #else
     #define MY__cpuidex(info, func, func2)  __cpuid(info, func)
     #pragma message("======== (INCORRECT ?) cpuid WAS USED ========")
  #endif
#endif




void MyCPUID(UInt32 function, UInt32 *a, UInt32 *b, UInt32 *c, UInt32 *d)
{
  #ifdef USE_ASM

  #ifdef _MSC_VER

  UInt32 a2, b2, c2, d2;
  __asm xor EBX, EBX;
  __asm xor ECX, ECX;
  __asm xor EDX, EDX;
  __asm mov EAX, function;
  __asm cpuid;
  __asm mov a2, EAX;
  __asm mov b2, EBX;
  __asm mov c2, ECX;
  __asm mov d2, EDX;

  *a = a2;
  *b = b2;
  *c = c2;
  *d = d2;

  #else

  __asm__ __volatile__ (
  #if defined(MY_CPU_AMD64) && defined(__PIC__)
    "mov %%rbx, %%rdi;"
    "cpuid;"
    "xchg %%rbx, %%rdi;"
    : "=a" (*a) ,
      "=D" (*b) ,
  #elif defined(MY_CPU_X86) && defined(__PIC__)
    "mov %%ebx, %%edi;"
    "cpuid;"
    "xchgl %%ebx, %%edi;"
    : "=a" (*a) ,
      "=D" (*b) ,
  #else
    "cpuid"
    : "=a" (*a) ,
      "=b" (*b) ,
  #endif
      "=c" (*c) ,
      "=d" (*d)
    : "0" (function), "c"(0) ) ;

  #endif
  
  #else

  int CPUInfo[4];

  MY__cpuidex(CPUInfo, (int)function, 0);

  *a = (UInt32)CPUInfo[0];
  *b = (UInt32)CPUInfo[1];
  *c = (UInt32)CPUInfo[2];
  *d = (UInt32)CPUInfo[3];

  #endif
}

BoolInt x86cpuid_CheckAndRead(Cx86cpuid *p)
{
  CHECK_CPUID_IS_SUPPORTED
  MyCPUID(0, &p->maxFunc, &p->vendor[0], &p->vendor[2], &p->vendor[1]);
  MyCPUID(1, &p->ver, &p->b, &p->c, &p->d);
  return True;
}

static const UInt32 kVendors[][3] =
{
  { 0x756E6547, 0x49656E69, 0x6C65746E},
  { 0x68747541, 0x69746E65, 0x444D4163},
  { 0x746E6543, 0x48727561, 0x736C7561}
};

int x86cpuid_GetFirm(const Cx86cpuid *p)
{
  unsigned i;
  for (i = 0; i < sizeof(kVendors) / sizeof(kVendors[i]); i++)
  {
    const UInt32 *v = kVendors[i];
    if (v[0] == p->vendor[0] &&
        v[1] == p->vendor[1] &&
        v[2] == p->vendor[2])
      return (int)i;
  }
  return -1;
}

BoolInt CPU_Is_InOrder()
{
  Cx86cpuid p;
  int firm;
  UInt32 family, model;
  if (!x86cpuid_CheckAndRead(&p))
    return True;

  family = x86cpuid_GetFamily(p.ver);
  model = x86cpuid_GetModel(p.ver);
  
  firm = x86cpuid_GetFirm(&p);

  switch (firm)
  {
    case CPU_FIRM_INTEL: return (family < 6 || (family == 6 && (
        /* In-Order Atom CPU */
           model == 0x1C  /* 45 nm, N4xx, D4xx, N5xx, D5xx, 230, 330 */
        || model == 0x26  /* 45 nm, Z6xx */
        || model == 0x27  /* 32 nm, Z2460 */
        || model == 0x35  /* 32 nm, Z2760 */
        || model == 0x36  /* 32 nm, N2xxx, D2xxx */
        )));
    case CPU_FIRM_AMD: return (family < 5 || (family == 5 && (model < 6 || model == 0xA)));
    case CPU_FIRM_VIA: return (family < 6 || (family == 6 && model < 0xF));
  }
  return True;
}

#if !defined(MY_CPU_AMD64) && defined(_WIN32)
#include <windows.h>
static BoolInt CPU_Sys_Is_SSE_Supported()
{
  OSVERSIONINFO vi;
  vi.dwOSVersionInfoSize = sizeof(vi);
  if (!GetVersionEx(&vi))
    return False;
  return (vi.dwMajorVersion >= 5);
}
#define CHECK_SYS_SSE_SUPPORT if (!CPU_Sys_Is_SSE_Supported()) return False;
#else
#define CHECK_SYS_SSE_SUPPORT
#endif


static UInt32 X86_CPUID_ECX_Get_Flags()
{
  Cx86cpuid p;
  CHECK_SYS_SSE_SUPPORT
  if (!x86cpuid_CheckAndRead(&p))
    return 0;
  return p.c;
}

BoolInt CPU_IsSupported_AES()
{
  return (X86_CPUID_ECX_Get_Flags() >> 25) & 1;
}

BoolInt CPU_IsSupported_SSSE3()
{
  return (X86_CPUID_ECX_Get_Flags() >> 9) & 1;
}

BoolInt CPU_IsSupported_SSE41()
{
  return (X86_CPUID_ECX_Get_Flags() >> 19) & 1;
}

BoolInt CPU_IsSupported_SHA()
{
  Cx86cpuid p;
  CHECK_SYS_SSE_SUPPORT
  if (!x86cpuid_CheckAndRead(&p))
    return False;

  if (p.maxFunc < 7)
    return False;
  {
    UInt32 d[4] = { 0 };
    MyCPUID(7, &d[0], &d[1], &d[2], &d[3]);
    return (d[1] >> 29) & 1;
  }
}

// #include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

BoolInt CPU_IsSupported_VAES_AVX2()
{
  Cx86cpuid p;
  CHECK_SYS_SSE_SUPPORT

  #ifdef _WIN32
  #define MY__PF_XSAVE_ENABLED  17
  if (!IsProcessorFeaturePresent(MY__PF_XSAVE_ENABLED))
    return False;
  #endif

  if (!x86cpuid_CheckAndRead(&p))
    return False;
  if (p.maxFunc < 7)
    return False;
  {
    UInt32 d[4] = { 0 };
    MyCPUID(7, &d[0], &d[1], &d[2], &d[3]);
    // printf("\ncpuid(7): ebx=%8x ecx=%8x\n", d[1], d[2]);
    return 1
      & (d[1] >> 5) // avx2
      // & (d[1] >> 31) // avx512vl
      & (d[2] >> 9); // vaes // VEX-256/EVEX
  }
}

BoolInt CPU_IsSupported_PageGB()
{
  Cx86cpuid cpuid;
  if (!x86cpuid_CheckAndRead(&cpuid))
    return False;
  {
    UInt32 d[4] = { 0 };
    MyCPUID(0x80000000, &d[0], &d[1], &d[2], &d[3]);
    if (d[0] < 0x80000001)
      return False;
  }
  {
    UInt32 d[4] = { 0 };
    MyCPUID(0x80000001, &d[0], &d[1], &d[2], &d[3]);
    return (d[3] >> 26) & 1;
  }
}


#elif defined(MY_CPU_ARM_OR_ARM64)

#ifdef _WIN32

#include <windows.h>

BoolInt CPU_IsSupported_CRC32()
  { return IsProcessorFeaturePresent(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) ? 1 : 0; }
BoolInt CPU_IsSupported_CRYPTO()
  { return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) ? 1 : 0; }

#else

#if defined(__APPLE__)

/*
#include <stdio.h>
#include <string.h>
static void Print_sysctlbyname(const char *name)
{
  size_t bufSize = 256;
  char buf[256];
  int res = sysctlbyname(name, &buf, &bufSize, NULL, 0);
  {
    int i;
    printf("\nres = %d : %s : '%s' : bufSize = %d, numeric", res, name, buf, (unsigned)bufSize);
    for (i = 0; i < 20; i++)
      printf(" %2x", (unsigned)(Byte)buf[i]);

  }
}
*/

BoolInt CPU_IsSupported_CRC32(void)
{
  /*
  Print_sysctlbyname("hw.pagesize");
  Print_sysctlbyname("machdep.cpu.brand_string");
  */

  UInt32 val = 0;
  if (My_sysctlbyname_Get_UInt32("hw.optional.armv8_crc32", &val) == 0 && val == 1)
    return 1;
  return 0;
}

#ifdef MY_CPU_ARM64
#define APPLE_CRYPTO_SUPPORT_VAL 1
#else
#define APPLE_CRYPTO_SUPPORT_VAL 0
#endif

BoolInt CPU_IsSupported_SHA1(void) { return APPLE_CRYPTO_SUPPORT_VAL; }
BoolInt CPU_IsSupported_SHA2(void) { return APPLE_CRYPTO_SUPPORT_VAL; }
BoolInt CPU_IsSupported_AES (void) { return APPLE_CRYPTO_SUPPORT_VAL; }


#else // __APPLE__

#include <sys/auxv.h>

#define USE_HWCAP

#ifdef USE_HWCAP

#include <asm/hwcap.h>

#ifdef MY_CPU_ARM64
  #define MY_HWCAP_CHECK_FUNC(name) \
  BoolInt CPU_IsSupported_ ## name() { return (getauxval(AT_HWCAP)  & (HWCAP_  ## name)) ? 1 : 0; }
#elif defined(MY_CPU_ARM)
  #define MY_HWCAP_CHECK_FUNC(name) \
  BoolInt CPU_IsSupported_ ## name() { return (getauxval(AT_HWCAP2) & (HWCAP2_ ## name)) ? 1 : 0; }
#endif

#else // USE_HWCAP

  #define MY_HWCAP_CHECK_FUNC(name) \
  BoolInt CPU_IsSupported_ ## name() { return 0; }

#endif // USE_HWCAP

MY_HWCAP_CHECK_FUNC (CRC32)
MY_HWCAP_CHECK_FUNC (SHA1)
MY_HWCAP_CHECK_FUNC (SHA2)
MY_HWCAP_CHECK_FUNC (AES)

#endif // __APPLE__
#endif // _WIN32

#endif // MY_CPU_ARM_OR_ARM64



#ifdef __APPLE__

#include <sys/sysctl.h>

int My_sysctlbyname_Get(const char *name, void *buf, size_t *bufSize)
{
  return sysctlbyname(name, buf, bufSize, NULL, 0);
}

int My_sysctlbyname_Get_UInt32(const char *name, UInt32 *val)
{
  size_t bufSize = sizeof(*val);
  int res = My_sysctlbyname_Get(name, val, &bufSize);
  if (res == 0 && bufSize != sizeof(*val))
    return EFAULT;
  return res;
}

#endif
