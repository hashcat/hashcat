/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_YESCRYPT_H
#define INC_HASH_YESCRYPT_H

#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth    8

#define PWXbytes        (PWXgather * PWXsimple * 8)
#define PWXwords        (PWXbytes / 4)
#define Sbytes          (3 * (1 << Swidth) * PWXsimple * 8)
#define Swords          (Sbytes / 4)
#define Smask           (((1 << Swidth) - 1) * PWXsimple * 8)
#define SBOX_THIRD_WORDS ((1 << Swidth) * PWXsimple * 2)

#define YESCRYPT_STATE_SZ   (128 * YESCRYPT_R)
#define YESCRYPT_SALSA_CNT4 16

#define YESCRYPT_PREHASH_NEEDED \
  (((YESCRYPT_FLAGS & 0x002) != 0) && \
   ((YESCRYPT_N / YESCRYPT_P) >= 256) && \
   (((YESCRYPT_N / YESCRYPT_P) * YESCRYPT_R) >= 0x20000))

#define YESCRYPT_PREHASH_N (YESCRYPT_N / 64)

typedef struct yescrypt_tmp
{
  u32 P[YESCRYPT_STATE_CNT4];
  u32 S[Swords];
  u32 passwd[8];
  u32 phase;
  u32 iter;
  u32 s_state;
  u32 w;

} yescrypt_tmp_t;

DECLSPEC u64  yescrypt_integerify (PRIVATE_AS const u32 *X, const u32 r);
DECLSPEC u64  yescrypt_p2floor (u64 x);
DECLSPEC u64  yescrypt_wrap (u64 x, u64 i);
DECLSPEC void yescrypt_salsa20_2 (PRIVATE_AS u32 *TI);
DECLSPEC void yescrypt_salsa20_8 (PRIVATE_AS u32 *TI);
DECLSPEC void yescrypt_blockmix_salsa8 (PRIVATE_AS u32 *X, const u32 r);
DECLSPEC void yescrypt_pwxform (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr);
DECLSPEC void yescrypt_blockmix_pwxform (PRIVATE_AS u32 *X, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r);
DECLSPEC void yescrypt_sbox_init (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, const u32 r);
DECLSPEC void yescrypt_smix1_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 i, const u32 flags);
DECLSPEC void yescrypt_smix2_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 flags);
DECLSPEC void yescrypt_simd_shuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r);
DECLSPEC void yescrypt_simd_unshuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r);

#endif
