/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "cpu_features.h"

static inline void cpuid (u32 leaf, u32 subleaf, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
  __cpuid_count (leaf, subleaf, *eax, *ebx, *ecx, *edx);
}

static inline u64 xgetbv (u32 index)
{
  u32 eax, edx;

  __asm__ volatile (".byte 0x0f, 0x01, 0xd0"
                    : "=a"(eax), "=d"(edx)
                    : "c"(index));

  return ((u64)edx << 32) | eax;
}

// Should always be present on 64 bit?
int cpu_supports_sse2 ()
{
  u32 eax, ebx, ecx, edx;

  cpuid(1, 0, &eax, &ebx, &ecx, &edx);

  return (edx & bit_SSE2) != 0;
}

int cpu_supports_ssse3 ()
{
  u32 eax, ebx, ecx, edx;

  cpuid (1, 0, &eax, &ebx, &ecx, &edx);

  return (ecx & bit_SSSE3) != 0;
}

int cpu_supports_xop ()
{
  u32 eax, ebx, ecx, edx;

  cpuid (0x80000000, 0, &eax, &ebx, &ecx, &edx);

  if (eax < 0x80000001)
  {
    return 0;
  }

  cpuid (0x80000001, 0, &eax, &ebx, &ecx, &edx);

  return (ecx & (1 << 11)) != 0; // No macro for XOP
}

int cpu_supports_avx2 ()
{
  u32 eax, ebx, ecx, edx;

  cpuid (1, 0, &eax, &ebx, &ecx, &edx);

  if (!(ecx & bit_OSXSAVE) || !(ecx & bit_AVX))
  {
    return 0;
  }

  if ((xgetbv(0) & 0x6) != 0x6) // XMM and YMM state
  {
    return 0;
  }

  cpuid (7, 0, &eax, &ebx, &ecx, &edx);

  return (ebx & bit_AVX2) != 0;
}

int cpu_supports_avx512f ()
{
  u32 eax, ebx, ecx, edx;

  cpuid (1, 0, &eax, &ebx, &ecx, &edx);

  if (!(ecx & bit_OSXSAVE) || !(ecx & bit_AVX))
  {
    return 0;
  }

  if ((xgetbv(0) & 0xE6) != 0xE6)
  {
    return 0;
  }

  cpuid (7, 0, &eax, &ebx, &ecx, &edx);

  return (ebx & bit_AVX512F) != 0;
}

int cpu_supports_avx512vl ()
{
  u32 eax, ebx, ecx, edx;

  cpuid (1, 0, &eax, &ebx, &ecx, &edx);

  if (!(ecx & bit_OSXSAVE) || !(ecx & bit_AVX))
  {
    return 0;
  }

  if ((xgetbv(0) & 0xE6) != 0xE6)
  {
    return 0;
  }

  cpuid (7, 0, &eax, &ebx, &ecx, &edx);

  return (ebx & (1u << 31)) != 0;
}

int cpu_chipset_test ()
{
  #ifdef __SSE2__
  if (cpu_supports_sse2 () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with SSE2 but CPU does not support it.\n");

    return -1;
  }
  #endif

  #ifdef __SSSE3__
  if (cpu_supports_ssse3 () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with SSSE3 but CPU does not support it.\n");

    return -1;
  }
  #endif

  #ifdef __XOP__
  if (cpu_supports_xop () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with XOP but CPU does not support it.\n");

    return -1;
  }
  #endif

  #ifdef __AVX2__
  if (cpu_supports_avx2 () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with AVX2 but CPU does not support it.\n");

    return -1;
  }
  #endif

  #ifdef __AVX512F__
  if (cpu_supports_avx512f () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with AVX512F but CPU does not support it.\n");

    return -1;
  }
  #endif

  #ifdef __AVX512VL__
  if (cpu_supports_avx512vl () == 0)
  {
    fprintf (stderr, "ERROR: Compiled with AVX512VL but CPU does not support it.\n");

    return -1;
  }
  #endif

  return 0;
}
