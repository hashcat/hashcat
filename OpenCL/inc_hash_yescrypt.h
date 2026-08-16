/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_YESCRYPT_H
#define INC_HASH_YESCRYPT_H

// pwxform geometry, fixed by the yescrypt specification

#define PWXsimple 2
#define PWXgather 4
#define PWXrounds 6
#define Swidth    8

#define PWXbytes         (PWXgather * PWXsimple * 8)
#define PWXwords         (PWXbytes / 4)
#define Sbytes           (3 * (1 << Swidth) * PWXsimple * 8)
#define Swords           (Sbytes / 4)
#define Smask            (((1 << Swidth) - 1) * PWXsimple * 8)
#define SBOX_THIRD_WORDS ((1 << Swidth) * PWXsimple * 2)

// the only flag bit the kernel branches on. YESCRYPT_RW selects the read-write
// variant, where smix writes its blocks back to V instead of only reading them

#define YESCRYPT_FLAG_RW 0x002

// _SZ is a true size in bytes, _CNT4 is the same size counted in u32

#define YESCRYPT_STATE_SZ   (128 * YESCRYPT_R)
#define YESCRYPT_SALSA_CNT4 16

// yescrypt runs a cheaper pass over a smaller V first whenever the real pass is
// large enough for it to pay off. These are the conditions from the reference
// implementation, resolved at JIT time because N, r, p and the flags are known

#define YESCRYPT_PREHASH_NEEDED \
  (((YESCRYPT_FLAGS & YESCRYPT_FLAG_RW) != 0) && \
   ((YESCRYPT_N / YESCRYPT_P) >= 256) && \
   (((YESCRYPT_N / YESCRYPT_P) * YESCRYPT_R) >= 0x20000))

#define YESCRYPT_PREHASH_N (YESCRYPT_N / 64)

// The loop kernel is cooperative: one workgroup owns one hash, and the four
// pwxform lanes are threads 0 to 3 of that workgroup. Every thread count below
// PWXgather leaves lanes unprocessed and produces a wrong digest, so the module
// clamps the thread count to at least this.

#define COOP_PWX_LANES PWXgather

// The Sbox and the X block both move to local memory when they fit, decided by
// the module and passed in as -D COOP_SBOX_LDS or -D COOP_X_GLOBAL.

#ifdef COOP_SBOX_LDS
#define SBOX_AS LOCAL_AS
#else
#define SBOX_AS GLOBAL_AS
#endif

#ifdef COOP_X_GLOBAL
#define XBUF_AS GLOBAL_AS
#else
#define XBUF_AS LOCAL_AS
#endif

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

// The trailing letters say which address space each buffer lives in, in the
// order the parameters appear: p for private, g for global. Same convention as
// the scrypt pbkdf2 helpers.

DECLSPEC void yescrypt_pbkdf2_body_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf, const u32 out_len);
DECLSPEC void yescrypt_hmac_final_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf);
DECLSPEC void yescrypt_pbkdf2_ppp (PRIVATE_AS const u32 *pw_buf, const u32 pw_len, PRIVATE_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out_buf, const u32 out_len);
DECLSPEC void yescrypt_pbkdf2_pgp (PRIVATE_AS const u32 *pw_buf, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out_buf, const u32 out_len);
DECLSPEC void yescrypt_hmac_ppp (PRIVATE_AS const u32 *key_buf, const u32 key_len, PRIVATE_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *out_buf);
DECLSPEC void yescrypt_hmac_pgp (PRIVATE_AS const u32 *key_buf, const u32 key_len, GLOBAL_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *out_buf);

DECLSPEC u64  yescrypt_integerify (PRIVATE_AS const u32 *X, const u32 r);
DECLSPEC u64  yescrypt_p2floor (const u64 x);
DECLSPEC u64  yescrypt_wrap (const u64 x, const u64 i);
DECLSPEC void yescrypt_simd_shuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r);
DECLSPEC void yescrypt_simd_unshuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r);
DECLSPEC void yescrypt_salsa20_2 (PRIVATE_AS u32 *TI);
DECLSPEC void yescrypt_salsa20_8 (PRIVATE_AS u32 *TI);
DECLSPEC void yescrypt_blockmix_salsa8 (PRIVATE_AS u32 *X, const u32 r);
DECLSPEC void yescrypt_pwxform (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr);
DECLSPEC void yescrypt_blockmix_pwxform (PRIVATE_AS u32 *X, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r);
DECLSPEC void yescrypt_sbox_init (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox);
DECLSPEC void yescrypt_smix1_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 i, const u32 flags);
DECLSPEC void yescrypt_smix2_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 flags);
DECLSPEC void yescrypt_kdf_setup (GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *passwd, PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr);
DECLSPEC void yescrypt_prehash_passwd (PRIVATE_AS const u32 *B, PRIVATE_AS u32 *passwd);
DECLSPEC void yescrypt_prehash_smix (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 prehash_N, const u32 flags);

DECLSPEC u64  yescrypt_coop_integerify (XBUF_AS const u32 *X);
DECLSPEC void yescrypt_coop_blockmix_pwxform (XBUF_AS u32 *X, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 lid);
DECLSPEC void yescrypt_coop_smix1_step (XBUF_AS u32 *X, GLOBAL_AS u32 *V, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 i, const u32 lid, const u32 lsz, const u32 flags);
DECLSPEC void yescrypt_coop_smix2_step (XBUF_AS u32 *X, GLOBAL_AS u32 *V, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 lid, const u32 lsz, const u32 flags);

DECLSPEC void yescrypt_kdf_init (GLOBAL_AS const u32 *pw_buf, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, GLOBAL_AS yescrypt_tmp_t *tmp, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 gid);
DECLSPEC void yescrypt_smix_loop (XBUF_AS u32 *X, SBOX_AS u32 *sbox, GLOBAL_AS yescrypt_tmp_t *tmp, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 bid, const u32 lid, const u32 lsz, const u32 loop_cnt);
DECLSPEC void yescrypt_kdf_final (GLOBAL_AS yescrypt_tmp_t *tmp, PRIVATE_AS u32 *dk);

#endif
