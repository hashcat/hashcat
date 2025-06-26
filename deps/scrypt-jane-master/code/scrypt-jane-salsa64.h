#define SCRYPT_MIX_BASE "Salsa64/8"

typedef uint64_t scrypt_mix_word_t;

#define SCRYPT_WORDTO8_LE U64TO8_LE
#define SCRYPT_WORD_ENDIAN_SWAP U64_SWAP

#define SCRYPT_BLOCK_BYTES 128
#define SCRYPT_BLOCK_WORDS (SCRYPT_BLOCK_BYTES / sizeof(scrypt_mix_word_t))

/* must have these here in case block bytes is ever != 64 */
#include "scrypt-jane-romix-basic.h"

#include "scrypt-jane-mix_salsa64-avx2.h"
#include "scrypt-jane-mix_salsa64-xop.h"
#include "scrypt-jane-mix_salsa64-avx.h"
#include "scrypt-jane-mix_salsa64-ssse3.h"
#include "scrypt-jane-mix_salsa64-sse2.h"
#include "scrypt-jane-mix_salsa64.h"

#if defined(SCRYPT_SALSA64_AVX2)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_avx2
	#define SCRYPT_ROMIX_FN scrypt_ROMix_avx2
	#define SCRYPT_ROMIX_TANGLE_FN salsa64_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa64_core_tangle_sse2
	#include "scrypt-jane-romix-template.h"
#endif

#if defined(SCRYPT_SALSA64_XOP)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_xop
	#define SCRYPT_ROMIX_FN scrypt_ROMix_xop
	#define SCRYPT_ROMIX_TANGLE_FN salsa64_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa64_core_tangle_sse2
	#include "scrypt-jane-romix-template.h"
#endif

#if defined(SCRYPT_SALSA64_AVX)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_avx
	#define SCRYPT_ROMIX_FN scrypt_ROMix_avx
	#define SCRYPT_ROMIX_TANGLE_FN salsa64_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa64_core_tangle_sse2
	#include "scrypt-jane-romix-template.h"
#endif

#if defined(SCRYPT_SALSA64_SSSE3)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_ssse3
	#define SCRYPT_ROMIX_FN scrypt_ROMix_ssse3
	#define SCRYPT_ROMIX_TANGLE_FN salsa64_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa64_core_tangle_sse2
	#include "scrypt-jane-romix-template.h"
#endif

#if defined(SCRYPT_SALSA64_SSE2)
	#define SCRYPT_CHUNKMIX_FN scrypt_ChunkMix_sse2
	#define SCRYPT_ROMIX_FN scrypt_ROMix_sse2
	#define SCRYPT_ROMIX_TANGLE_FN salsa64_core_tangle_sse2
	#define SCRYPT_ROMIX_UNTANGLE_FN salsa64_core_tangle_sse2
	#include "scrypt-jane-romix-template.h"
#endif

/* cpu agnostic */
#define SCRYPT_ROMIX_FN scrypt_ROMix_basic
#define SCRYPT_MIX_FN salsa64_core_basic
#define SCRYPT_ROMIX_TANGLE_FN scrypt_romix_convert_endian
#define SCRYPT_ROMIX_UNTANGLE_FN scrypt_romix_convert_endian
#include "scrypt-jane-romix-template.h"

#if !defined(SCRYPT_CHOOSE_COMPILETIME)
static scrypt_ROMixfn
scrypt_getROMix(void) {
	size_t cpuflags = detect_cpu();

#if defined(SCRYPT_SALSA64_AVX2)
	if (cpuflags & cpu_avx2)
		return scrypt_ROMix_avx2;
	else
#endif

#if defined(SCRYPT_SALSA64_XOP)
	if (cpuflags & cpu_xop)
		return scrypt_ROMix_xop;
	else
#endif

#if defined(SCRYPT_SALSA64_AVX)
	if (cpuflags & cpu_avx)
		return scrypt_ROMix_avx;
	else
#endif

#if defined(SCRYPT_SALSA64_SSSE3)
	if (cpuflags & cpu_ssse3)
		return scrypt_ROMix_ssse3;
	else
#endif

#if defined(SCRYPT_SALSA64_SSE2)
	if (cpuflags & cpu_sse2)
		return scrypt_ROMix_sse2;
	else
#endif

	return scrypt_ROMix_basic;
}
#endif


#if defined(SCRYPT_TEST_SPEED)
static size_t
available_implementations(void) {
	size_t cpuflags = detect_cpu();
	size_t flags = 0;

#if defined(SCRYPT_SALSA64_AVX2)
	if (cpuflags & cpu_avx2)
		flags |= cpu_avx2;
#endif

#if defined(SCRYPT_SALSA64_XOP)
	if (cpuflags & cpu_xop)
		flags |= cpu_xop;
#endif

#if defined(SCRYPT_SALSA64_AVX)
	if (cpuflags & cpu_avx)
		flags |= cpu_avx;
#endif

#if defined(SCRYPT_SALSA64_SSSE3)
	if (cpuflags & cpu_ssse3)
		flags |= cpu_ssse3;
#endif

#if defined(SCRYPT_SALSA64_SSE2)
	if (cpuflags & cpu_sse2)
		flags |= cpu_sse2;
#endif

	return flags;
}
#endif

static int
scrypt_test_mix(void) {
	static const uint8_t expected[16] = {
		0xf8,0x92,0x9b,0xf8,0xcc,0x1d,0xce,0x2e,0x13,0x82,0xac,0x96,0xb2,0x6c,0xee,0x2c,
	};

	int ret = 1;
	size_t cpuflags = detect_cpu();

#if defined(SCRYPT_SALSA64_AVX2)
	if (cpuflags & cpu_avx2)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_avx2, salsa64_core_tangle_sse2, salsa64_core_tangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA64_XOP)
	if (cpuflags & cpu_xop)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_xop, salsa64_core_tangle_sse2, salsa64_core_tangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA64_AVX)
	if (cpuflags & cpu_avx)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_avx, salsa64_core_tangle_sse2, salsa64_core_tangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA64_SSSE3)
	if (cpuflags & cpu_ssse3)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_ssse3, salsa64_core_tangle_sse2, salsa64_core_tangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA64_SSE2)
	if (cpuflags & cpu_sse2)
		ret &= scrypt_test_mix_instance(scrypt_ChunkMix_sse2, salsa64_core_tangle_sse2, salsa64_core_tangle_sse2, expected);
#endif

#if defined(SCRYPT_SALSA64_BASIC)
	ret &= scrypt_test_mix_instance(scrypt_ChunkMix_basic, scrypt_romix_convert_endian, scrypt_romix_convert_endian, expected);
#endif

	return ret;
}

