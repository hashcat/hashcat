/*
 * xxHash - Extremely Fast Hash algorithm
 * Copyright (C) 2020 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */


#if defined (__cplusplus)
extern "C" {
#endif

/*
 * Dispatcher code for XXH3 on x86-based targets.
 */
#if !(defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64))
#  error "Dispatching is currently only supported on x86 and x86_64."
#endif

#ifndef __GNUC__
#  error "Dispatching requires __attribute__((__target__)) capability"
#endif

#define XXH_DISPATCH_AVX2    /* enable dispatch towards AVX2 */
#define XXH_DISPATCH_AVX512  /* enable dispatch towards AVX512 */

#ifdef XXH_DISPATCH_DEBUG
/* debug logging */
#  include <stdio.h>
#  define XXH_debugPrint(str) { fprintf(stderr, "DEBUG: xxHash dispatch: %s \n", str); fflush(NULL); }
#else
#  define XXH_debugPrint(str) ((void)0)
#  undef NDEBUG /* avoid redefinition */
#  define NDEBUG
#endif
#include <assert.h>

#if defined(__GNUC__)
#  include <immintrin.h> /* sse2 */
#  include <emmintrin.h> /* avx2 */
#elif defined(_MSC_VER)
#  include <intrin.h>
#endif

#define XXH_INLINE_ALL
#define XXH_X86DISPATCH
#define XXH_TARGET_AVX512 __attribute__((__target__("avx512f")))
#define XXH_TARGET_AVX2 __attribute__((__target__("avx2")))
#define XXH_TARGET_SSE2 __attribute__((__target__("sse2")))
#include "xxhash.h"

/*
 * Modified version of Intel's guide
 * https://software.intel.com/en-us/articles/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family
 */
#if defined(_MSC_VER)
# include <intrin.h>
#endif

/*
 * Support both AT&T and Intel dialects
 *
 * GCC doesn't convert AT&T syntax to Intel syntax, and will error out if
 * compiled with -masm=intel. Instead, it supports dialect switching with
 * curly braces: { AT&T syntax | Intel syntax }
 *
 * Clang's integrated assembler automatically converts AT&T syntax to Intel if
 * needed, making the dialect switching useless (it isn't even supported).
 *
 * Note: Comments are written in the inline assembly itself.
 */
#ifdef __clang__
#  define I_ATT(intel, att) att "\n\t"
#else
#  define I_ATT(intel, att) "{" att "|" intel "}\n\t"
#endif


static void XXH_cpuid(xxh_u32 eax, xxh_u32 ecx, xxh_u32* abcd)
{
#if defined(_MSC_VER)
    __cpuidex(abcd, eax, ecx);
#else
    xxh_u32 ebx, edx;
# if defined(__i386__) && defined(__PIC__)
    __asm__(
        "# Call CPUID\n\t"
        "#\n\t"
        "# On 32-bit x86 with PIC enabled, we are not allowed to overwrite\n\t"
        "# EBX, so we use EDI instead.\n\t"
        I_ATT("mov     edi, ebx",   "movl    %%ebx, %%edi")
        I_ATT("cpuid",              "cpuid"               )
        I_ATT("xchg    edi, ebx",   "xchgl   %%ebx, %%edi")
        : "=D" (ebx),
# else
    __asm__(
        "# Call CPUID\n\t"
        I_ATT("cpuid",              "cpuid")
        : "=b" (ebx),
# endif
              "+a" (eax), "+c" (ecx), "=d" (edx));
    abcd[0] = eax;
    abcd[1] = ebx;
    abcd[2] = ecx;
    abcd[3] = edx;
#endif
}

#if defined(XXH_DISPATCH_AVX2) || defined(XXH_DISPATCH_AVX512)
/*
 * While the CPU may support AVX2, the operating system might not properly save
 * the full YMM/ZMM registers.
 *
 * xgetbv is used for detecting this: Any compliant operating system will define
 * a set of flags in the xcr0 register indicating how it saves the AVX registers.
 *
 * You can manually disable this flag on Windows by running, as admin:
 *
 *   bcdedit.exe /set xsavedisable 1
 *
 * and rebooting. Run the same command with 0 to re-enable it.
 */
static xxh_u64 XXH_xgetbv(void)
{
#if defined(_MSC_VER)
    return _xgetbv(0);  /* min VS2010 SP1 compiler is required */
#else
    xxh_u32 xcr0_lo, xcr0_hi;
    __asm__(
        "# Call XGETBV\n\t"
        "#\n\t"
        "# Older assemblers (e.g. macOS's ancient GAS version) don't support\n\t"
        "# the XGETBV opcode, so we encode it by hand instead.\n\t"
        "# See <https://github.com/asmjit/asmjit/issues/78> for details.\n\t"
        ".byte   0x0f, 0x01, 0xd0\n\t"
       : "=a" (xcr0_lo), "=d" (xcr0_hi) : "c" (0));
    return xcr0_lo | ((xxh_u64)xcr0_hi << 32);
#endif
}
#endif

#define SSE2_CPUID_MASK (1 << 26)
#define OSXSAVE_CPUID_MASK ((1 << 26) | (1 << 27))
#define AVX2_CPUID_MASK (1 << 5)
#define AVX2_XGETBV_MASK ((1 << 2) | (1 << 1))
#define AVX512F_CPUID_MASK (1 << 16)
#define AVX512F_XGETBV_MASK ((7 << 5) | (1 << 2) | (1 << 1))

/* Returns the best XXH3 implementation */
static int XXH_featureTest(void)
{
    xxh_u32 abcd[4];
    xxh_u32 max_leaves;
    int best = XXH_SCALAR;
#if defined(XXH_DISPATCH_AVX2) || defined(XXH_DISPATCH_AVX512)
    xxh_u64 xgetbv_val;
#endif
#if defined(__GNUC__) && defined(__i386__)
    xxh_u32 cpuid_supported;
    __asm__(
        "# For the sake of ruthless backwards compatibility, check if CPUID\n\t"
        "# is supported in the EFLAGS on i386.\n\t"
        "# This is not necessary on x86_64 - CPUID is mandatory.\n\t"
        "#   The ID flag (bit 21) in the EFLAGS register indicates support\n\t"
        "#   for the CPUID instruction. If a software procedure can set and\n\t"
        "#   clear this flag, the processor executing the procedure supports\n\t"
        "#   the CPUID instruction.\n\t"
        "#   <https://c9x.me/x86/html/file_module_x86_id_45.html>\n\t"
        "#\n\t"
        "# Routine is from <https://wiki.osdev.org/CPUID>.\n\t"

        "# Save EFLAGS\n\t"
        I_ATT("pushfd",                           "pushfl"                    )
        "# Store EFLAGS\n\t"
        I_ATT("pushfd",                           "pushfl"                    )
        "# Invert the ID bit in stored EFLAGS\n\t"
        I_ATT("xor     dword ptr[esp], 0x200000", "xorl    $0x200000, (%%esp)")
        "# Load stored EFLAGS (with ID bit inverted)\n\t"
        I_ATT("popfd",                            "popfl"                     )
        "# Store EFLAGS again (ID bit may or not be inverted)\n\t"
        I_ATT("pushfd",                           "pushfl"                    )
        "# eax = modified EFLAGS (ID bit may or may not be inverted)\n\t"
        I_ATT("pop     eax",                      "popl    %%eax"             )
        "# eax = whichever bits were changed\n\t"
        I_ATT("xor     eax, dword ptr[esp]",      "xorl    (%%esp), %%eax"    )
        "# Restore original EFLAGS\n\t"
        I_ATT("popfd",                            "popfl"                     )
        "# eax = zero if ID bit can't be changed, else non-zero\n\t"
        I_ATT("and     eax, 0x200000",            "andl    $0x200000, %%eax"  )
        : "=a" (cpuid_supported) :: "cc");

    if (XXH_unlikely(!cpuid_supported)) {
        XXH_debugPrint("CPUID support is not detected!");
        return best;
    }

#endif
    /* Check how many CPUID pages we have */
    XXH_cpuid(0, 0, abcd);
    max_leaves = abcd[0];

    /* Shouldn't happen on hardware, but happens on some QEMU configs. */
    if (XXH_unlikely(max_leaves == 0)) {
        XXH_debugPrint("Max CPUID leaves == 0!");
        return best;
    }

    /* Check for SSE2, OSXSAVE and xgetbv */
    XXH_cpuid(1, 0, abcd);

    /*
     * Test for SSE2. The check is redundant on x86_64, but it doesn't hurt.
     */
    if (XXH_unlikely((abcd[3] & SSE2_CPUID_MASK) != SSE2_CPUID_MASK))
        return best;

    XXH_debugPrint("SSE2 support detected.");

    best = XXH_SSE2;
#if defined(XXH_DISPATCH_AVX2) || defined(XXH_DISPATCH_AVX512)
    /* Make sure we have enough leaves */
    if (XXH_unlikely(max_leaves < 7))
        return best;

    /* Test for OSXSAVE and XGETBV */
    if ((abcd[2] & OSXSAVE_CPUID_MASK) != OSXSAVE_CPUID_MASK)
        return best;

    /* CPUID check for AVX features */
    XXH_cpuid(7, 0, abcd);

    xgetbv_val = XXH_xgetbv();
#if defined(XXH_DISPATCH_AVX2)
    /* Validate that AVX2 is supported by the CPU */
    if ((abcd[1] & AVX2_CPUID_MASK) != AVX2_CPUID_MASK)
        return best;

    /* Validate that the OS supports YMM registers */
    if ((xgetbv_val & AVX2_XGETBV_MASK) != AVX2_XGETBV_MASK) {
        XXH_debugPrint("AVX2 supported by the CPU, but not the OS.");
        return best;
    }

    /* AVX2 supported */
    XXH_debugPrint("AVX2 support detected.");
    best = XXH_AVX2;
#endif
#if defined(XXH_DISPATCH_AVX512)
    /* Check if AVX512F is supported by the CPU */
    if ((abcd[1] & AVX512F_CPUID_MASK) != AVX512F_CPUID_MASK) {
        XXH_debugPrint("AVX512F not supported by CPU");
        return best;
    }

    /* Validate that the OS supports ZMM registers */
    if ((xgetbv_val & AVX512F_XGETBV_MASK) != AVX512F_XGETBV_MASK) {
        XXH_debugPrint("AVX512F supported by the CPU, but not the OS.");
        return best;
    }

    /* AVX512F supported */
    XXH_debugPrint("AVX512F support detected.");
    best = XXH_AVX512;
#endif
#endif
    return best;
}


/* ===   Vector implementations   === */

/* ===   XXH3, default variants   === */

XXH_NO_INLINE XXH64_hash_t
XXHL64_default_scalar(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH64_hash_t
XXHL64_default_sse2(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH64_hash_t
XXHL64_default_avx2(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH64_hash_t
XXHL64_default_avx512(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_64b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ===   XXH3, Seeded variants   === */

XXH_NO_INLINE XXH64_hash_t
XXHL64_seed_scalar(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_64b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar, XXH3_initCustomSecret_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH64_hash_t
XXHL64_seed_sse2(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_64b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2, XXH3_initCustomSecret_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH64_hash_t
XXHL64_seed_avx2(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_64b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2, XXH3_initCustomSecret_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH64_hash_t
XXHL64_seed_avx512(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_64b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512, XXH3_initCustomSecret_avx512);
}
#endif

/* ===   XXH3, Secret variants   === */

XXH_NO_INLINE XXH64_hash_t
XXHL64_secret_scalar(const void* XXH_RESTRICT input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_hashLong_64b_internal(input, len, secret, secretLen,
                    XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH64_hash_t
XXHL64_secret_sse2(const void* XXH_RESTRICT input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_hashLong_64b_internal(input, len, secret, secretLen,
                    XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH64_hash_t
XXHL64_secret_avx2(const void* XXH_RESTRICT input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_hashLong_64b_internal(input, len, secret, secretLen,
                    XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH64_hash_t
XXHL64_secret_avx512(const void* XXH_RESTRICT input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_hashLong_64b_internal(input, len, secret, secretLen,
                    XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ===   XXH3 update variants   === */

XXH_NO_INLINE XXH_errorcode
XXH3_64bits_update_scalar(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH_errorcode
XXH3_64bits_update_sse2(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH_errorcode
XXH3_64bits_update_avx2(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH_errorcode
XXH3_64bits_update_avx512(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ===   XXH128 default variants   === */

XXH_NO_INLINE XXH128_hash_t
XXHL128_default_scalar(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_128b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH128_hash_t
XXHL128_default_sse2(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_128b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH128_hash_t
XXHL128_default_avx2(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_128b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH128_hash_t
XXHL128_default_avx512(const void* XXH_RESTRICT input, size_t len)
{
    return XXH3_hashLong_128b_internal(input, len, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ===   XXH128 Secret variants   === */

XXH_NO_INLINE XXH128_hash_t
XXHL128_secret_scalar(const void* XXH_RESTRICT input, size_t len, const void* XXH_RESTRICT secret, size_t secretLen)
{
    return XXH3_hashLong_128b_internal(input, len, (const xxh_u8*)secret, secretLen,
                    XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH128_hash_t
XXHL128_secret_sse2(const void* XXH_RESTRICT input, size_t len, const void* XXH_RESTRICT secret, size_t secretLen)
{
    return XXH3_hashLong_128b_internal(input, len, (const xxh_u8*)secret, secretLen,
                    XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH128_hash_t
XXHL128_secret_avx2(const void* XXH_RESTRICT input, size_t len, const void* XXH_RESTRICT secret, size_t secretLen)
{
    return XXH3_hashLong_128b_internal(input, len, (const xxh_u8*)secret, secretLen,
                    XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH128_hash_t
XXHL128_secret_avx512(const void* XXH_RESTRICT input, size_t len, const void* XXH_RESTRICT secret, size_t secretLen)
{
    return XXH3_hashLong_128b_internal(input, len, (const xxh_u8*)secret, secretLen,
                    XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ===   XXH128 Seeded variants   === */

XXH_NO_INLINE XXH128_hash_t
XXHL128_seed_scalar(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_128b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar, XXH3_initCustomSecret_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH128_hash_t
XXHL128_seed_sse2(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_128b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2, XXH3_initCustomSecret_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH128_hash_t
XXHL128_seed_avx2(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_128b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2, XXH3_initCustomSecret_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH128_hash_t
XXHL128_seed_avx512(const void* XXH_RESTRICT input, size_t len, XXH64_hash_t seed)
{
    return XXH3_hashLong_128b_withSeed_internal(input, len, seed,
                    XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512, XXH3_initCustomSecret_avx512);
}
#endif

/* ===   XXH128 update variants   === */

XXH_NO_INLINE XXH_errorcode
XXH3_128bits_update_scalar(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_scalar, XXH3_scrambleAcc_scalar);
}

XXH_NO_INLINE XXH_TARGET_SSE2 XXH_errorcode
XXH3_128bits_update_sse2(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_sse2, XXH3_scrambleAcc_sse2);
}

#ifdef XXH_DISPATCH_AVX2
XXH_NO_INLINE XXH_TARGET_AVX2 XXH_errorcode
XXH3_128bits_update_avx2(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_avx2, XXH3_scrambleAcc_avx2);
}
#endif

#ifdef XXH_DISPATCH_AVX512
XXH_NO_INLINE XXH_TARGET_AVX512 XXH_errorcode
XXH3_128bits_update_avx512(XXH3_state_t* state, const void* input, size_t len)
{
    return XXH3_update(state, (const xxh_u8*)input, len,
                       XXH3_accumulate_512_avx512, XXH3_scrambleAcc_avx512);
}
#endif

/* ====    Dispatchers    ==== */

typedef XXH64_hash_t (*XXH3_dispatchx86_hashLong64_default)(const void* XXH_RESTRICT, size_t);

typedef XXH64_hash_t (*XXH3_dispatchx86_hashLong64_withSeed)(const void* XXH_RESTRICT, size_t, XXH64_hash_t);

typedef XXH64_hash_t (*XXH3_dispatchx86_hashLong64_withSecret)(const void* XXH_RESTRICT, size_t, const void* XXH_RESTRICT, size_t);

typedef XXH_errorcode (*XXH3_dispatchx86_update)(XXH3_state_t*, const void*, size_t);

typedef struct {
    XXH3_dispatchx86_hashLong64_default    hashLong64_default;
    XXH3_dispatchx86_hashLong64_withSeed   hashLong64_seed;
    XXH3_dispatchx86_hashLong64_withSecret hashLong64_secret;
    XXH3_dispatchx86_update                update;
} dispatchFunctions_s;

static dispatchFunctions_s g_dispatch = { NULL, NULL, NULL, NULL};

#define NB_DISPATCHES 4
static const dispatchFunctions_s k_dispatch[NB_DISPATCHES] = {
        /* scalar */ { XXHL64_default_scalar, XXHL64_seed_scalar, XXHL64_secret_scalar, XXH3_64bits_update_scalar },
        /* sse2   */ { XXHL64_default_sse2,   XXHL64_seed_sse2,   XXHL64_secret_sse2,   XXH3_64bits_update_sse2 },
#ifdef XXH_DISPATCH_AVX2
        /* avx2   */ { XXHL64_default_avx2,   XXHL64_seed_avx2,   XXHL64_secret_avx2,   XXH3_64bits_update_avx2 },
#else
        /* avx2 */ { NULL, NULL, NULL, NULL },
#endif
#ifdef XXH_DISPATCH_AVX512
        /* avx512 */ { XXHL64_default_avx512, XXHL64_seed_avx512, XXHL64_secret_avx512, XXH3_64bits_update_avx512 }
#else
        /* avx512 */ { NULL, NULL, NULL, NULL }
#endif
};

typedef XXH128_hash_t (*XXH3_dispatchx86_hashLong128_default)(const void* XXH_RESTRICT, size_t);

typedef XXH128_hash_t (*XXH3_dispatchx86_hashLong128_withSeed)(const void* XXH_RESTRICT, size_t, XXH64_hash_t);

typedef XXH128_hash_t (*XXH3_dispatchx86_hashLong128_withSecret)(const void* XXH_RESTRICT, size_t, const void* XXH_RESTRICT, size_t);

typedef struct {
    XXH3_dispatchx86_hashLong128_default    hashLong128_default;
    XXH3_dispatchx86_hashLong128_withSeed   hashLong128_seed;
    XXH3_dispatchx86_hashLong128_withSecret hashLong128_secret;
    XXH3_dispatchx86_update                 update;
} dispatch128Functions_s;

static dispatch128Functions_s g_dispatch128 = { NULL, NULL, NULL, NULL };

static const dispatch128Functions_s k_dispatch128[NB_DISPATCHES] = {
        /* scalar */ { XXHL128_default_scalar, XXHL128_seed_scalar, XXHL128_secret_scalar, XXH3_128bits_update_scalar },
        /* sse2   */ { XXHL128_default_sse2,   XXHL128_seed_sse2,   XXHL128_secret_sse2,   XXH3_128bits_update_sse2 },
#ifdef XXH_DISPATCH_AVX2
        /* avx2   */ { XXHL128_default_avx2,   XXHL128_seed_avx2,   XXHL128_secret_avx2,   XXH3_128bits_update_avx2 },
#else
        /* avx2 */ { NULL, NULL, NULL, NULL },
#endif
#ifdef XXH_DISPATCH_AVX512
        /* avx512 */ { XXHL128_default_avx512, XXHL128_seed_avx512, XXHL128_secret_avx512, XXH3_128bits_update_avx512 }
#else
        /* avx512 */ { NULL, NULL, NULL, NULL }
#endif
};

static void setDispatch(void)
{
    int vecID = XXH_featureTest();
    XXH_STATIC_ASSERT(XXH_AVX512 == NB_DISPATCHES-1);
    assert(XXH_SCALAR <= vecID && vecID <= XXH_AVX512);
#ifndef XXH_DISPATCH_AVX512
    assert(vecID != XXH_AVX512);
#endif
#ifndef XXH_DISPATCH_AVX2
    assert(vecID != XXH_AVX2);
#endif
    g_dispatch = k_dispatch[vecID];
    g_dispatch128 = k_dispatch128[vecID];
}


/* ====    XXH3 public functions    ==== */

static XXH64_hash_t
XXH3_hashLong_64b_defaultSecret_selection(const void* input, size_t len,
                                          XXH64_hash_t seed64, const xxh_u8* secret, size_t secretLen)
{
    (void)seed64; (void)secret; (void)secretLen;
    if (g_dispatch.hashLong64_default == NULL) setDispatch();
    return g_dispatch.hashLong64_default(input, len);
}

XXH64_hash_t XXH3_64bits_dispatch(const void* input, size_t len)
{
    return XXH3_64bits_internal(input, len, 0, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_hashLong_64b_defaultSecret_selection);
}

static XXH64_hash_t
XXH3_hashLong_64b_withSeed_selection(const void* input, size_t len,
                                     XXH64_hash_t seed64, const xxh_u8* secret, size_t secretLen)
{
    (void)secret; (void)secretLen;
    if (g_dispatch.hashLong64_seed == NULL) setDispatch();
    return g_dispatch.hashLong64_seed(input, len, seed64);
}

XXH64_hash_t XXH3_64bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed)
{
    return XXH3_64bits_internal(input, len, seed, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_hashLong_64b_withSeed_selection);
}

static XXH64_hash_t
XXH3_hashLong_64b_withSecret_selection(const void* input, size_t len,
                                       XXH64_hash_t seed64, const xxh_u8* secret, size_t secretLen)
{
    (void)seed64;
    if (g_dispatch.hashLong64_secret == NULL) setDispatch();
    return g_dispatch.hashLong64_secret(input, len, secret, secretLen);
}

XXH64_hash_t XXH3_64bits_withSecret_dispatch(const void* input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_64bits_internal(input, len, 0, secret, secretLen, XXH3_hashLong_64b_withSecret_selection);
}

XXH_errorcode
XXH3_64bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len)
{
    if (g_dispatch.update == NULL) setDispatch();
    return g_dispatch.update(state, (const xxh_u8*)input, len);
}


/* ====    XXH128 public functions    ==== */

static XXH128_hash_t
XXH3_hashLong_128b_defaultSecret_selection(const void* input, size_t len,
                                           XXH64_hash_t seed64, const void* secret, size_t secretLen)
{
    (void)seed64; (void)secret; (void)secretLen;
    if (g_dispatch128.hashLong128_default == NULL) setDispatch();
    return g_dispatch128.hashLong128_default(input, len);
}

XXH128_hash_t XXH3_128bits_dispatch(const void* input, size_t len)
{
    return XXH3_128bits_internal(input, len, 0, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_hashLong_128b_defaultSecret_selection);
}

static XXH128_hash_t
XXH3_hashLong_128b_withSeed_selection(const void* input, size_t len,
                                     XXH64_hash_t seed64, const void* secret, size_t secretLen)
{
    (void)secret; (void)secretLen;
    if (g_dispatch128.hashLong128_seed == NULL) setDispatch();
    return g_dispatch128.hashLong128_seed(input, len, seed64);
}

XXH128_hash_t XXH3_128bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed)
{
    return XXH3_128bits_internal(input, len, seed, XXH3_kSecret, sizeof(XXH3_kSecret), XXH3_hashLong_128b_withSeed_selection);
}

static XXH128_hash_t
XXH3_hashLong_128b_withSecret_selection(const void* input, size_t len,
                                        XXH64_hash_t seed64, const void* secret, size_t secretLen)
{
    (void)seed64;
    if (g_dispatch128.hashLong128_secret == NULL) setDispatch();
    return g_dispatch128.hashLong128_secret(input, len, secret, secretLen);
}

XXH128_hash_t XXH3_128bits_withSecret_dispatch(const void* input, size_t len, const void* secret, size_t secretLen)
{
    return XXH3_128bits_internal(input, len, 0, secret, secretLen, XXH3_hashLong_128b_withSecret_selection);
}

XXH_errorcode
XXH3_128bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len)
{
    if (g_dispatch128.update == NULL) setDispatch();
    return g_dispatch128.update(state, (const xxh_u8*)input, len);
}

#if defined (__cplusplus)
}
#endif
