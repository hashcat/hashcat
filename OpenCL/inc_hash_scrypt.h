/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SCRYPT_H
#define INC_HASH_SCRYPT_H

#define GET_SCRYPT_SZ(r,p) (128 * (r) * (p))
#define GET_STATE_SZ(r)    (128 * (r))

// _SZ is true sizes as bytes
#define SCRYPT_SZ  GET_SCRYPT_SZ (SCRYPT_R, SCRYPT_P)
#define STATE_SZ   GET_STATE_SZ  (SCRYPT_R)

// _CNT is size as whatever /X datatype
#define SCRYPT_CNT4  (SCRYPT_SZ / 4)
#define STATE_CNT4   (STATE_SZ  / 4)

// this would be uint4, feels more natural than 16
#define SCRYPT_CNT44 ((SCRYPT_SZ / 4) / 4)
#define STATE_CNT44  ((STATE_SZ  / 4) / 4)

#define SALSA_SZ   64
#define SALSA_CNT4 (SALSA_SZ / 4)
#define SALSA_CNT44 ((SALSA_SZ / 4) / 4)

// the most iterations of the second loop one launch runs, which is the kernel_loops of every scrypt
// module, or N where that is less

#define SCRYPT_LOOP_MAX(n) (((n) < 2048) ? (n) : 2048)

// module_tune as the scrypt modules fill it, see scrypt_module_tune_variants (): the TMTO in the low
// byte, and whether the four-lane kernel runs.

#define SCRYPT_TUNE_TMTO(t)  ((t) & 0xff)
#define SCRYPT_TUNE_LANES4   (1u << 8)

// The per-candidate kernels read N from the salt rather than from the build, so one build for an r
// and p runs every N, the self-test hash's among them. Every salt of a session has the same N, see
// scrypt_module_extra_tmp_size (), and the self-test runs on a salt buffer of its own, so the first
// salt holds the N of every launch. SALT_POS_HOST would not do: under -a 9 it counts work items, and
// the four-lane kernel runs four of them for each candidate.

#define SCRYPT_SALT_N (salt_bufs[0].scrypt_N)

// The single-lane entry points that take SCRYPT_N and SCRYPT_TMTO as build constants stay for
// plugins written against them.

#ifndef SCRYPT_TMTO
#define SCRYPT_TMTO 0
#endif

// SCRYPT_COOP comes from the module and asks for the four-lane kernel to be built beside the
// single-lane one, for module_tune to choose between at run time. It is built where the kernel has a
// lane exchange of its own and the work group is 32 lanes. Anywhere else only the single-lane kernel
// is, and it runs on the same launch and the same V layout.

#if defined SCRYPT_COOP && defined FIXED_LOCAL_SIZE
#if FIXED_LOCAL_SIZE == 32
#if defined IS_CUDA || defined IS_HIP || (defined IS_NV && defined IS_GPU) || defined HC_SHFL_AMDGCN
#define SCRYPT_COOP_LANES
#define SCRYPT_COOP_GROUP (FIXED_LOCAL_SIZE / 4)
#endif
#endif
#endif

// Whether module_tune runs the four-lane kernel. Past r=2 the host lists only the four-lane kernel
// where it is built, see scrypt_tune_variants (), so the single-lane kernel stays out of the build
// there and its spills do not size the stack of the four-lane kernel.

#if defined SCRYPT_COOP_LANES
#if SCRYPT_R > 2
#define SCRYPT_COOP_RUNS(t) (true)
#else
#define SCRYPT_COOP_RUNS(t) (((t) & SCRYPT_TUNE_LANES4) != 0)
#endif
#endif

// Where the single-lane kernel is written so that X and T stay in registers, see scrypt_shuffle () in
// inc_hash_scrypt.cl: at r <= 2, and only where no four-lane kernel is built. Beside one, under HIP,
// autotune's short launches then timed the single-lane kernel faster than four lanes and it ran 8
// percent slower, and NVIDIA keeps the arrays in registers without it.

#if SCRYPT_R <= 2
#ifndef SCRYPT_COOP_LANES
#define SCRYPT_SINGLE_REGS
#endif
#endif

// should be safe, because in backend.c we use:
//    u64 size_extra_buffer1 = 4096;
//  size_extra_buffer1 += base_chunk_size;
// could be useless, pointers seem to be page aligned
//#define ALIGN_PTR_1k(p) ((GLOBAL_AS hc_uint4_t *) (((u64) (p) + 1023) & ~1023UL))

#if defined IS_INTEL_SDK

typedef struct
{
  u32 x, y, z, w;

} hc_uint4_t;

#else

typedef uint4 hc_uint4_t;

#endif

DECLSPEC hc_uint4_t xor_uint4 (const hc_uint4_t a, const hc_uint4_t b);

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  u32 in[SCRYPT_TMP_ELEM / 2];
  u32 out[SCRYPT_TMP_ELEM / 2];

} scrypt_tmp_t;

#endif
