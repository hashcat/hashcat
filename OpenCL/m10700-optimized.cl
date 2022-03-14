/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#if defined IS_AMD && defined IS_GPU
#define HC_INLINE
#elif defined IS_HIP
#define HC_INLINE HC_INLINE0
#else
#define HC_INLINE
#endif

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

typedef struct pdf17l8_tmp
{
  union
  {
    u32 dgst32[16];
    u64 dgst64[8];
  };

  u32 dgst_len;
  u32 W_len;

} pdf17l8_tmp_t;

typedef struct
{
  union
  {
    u32 dgst32[16];
    u64 dgst64[8];
  };

  u32 dgst_len;

  union
  {
    u32 W32[32];
    u64 W64[16];
  };

  u32 W_len;

} ctx_t;

DECLSPEC void orig_sha256_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = hc_swap32_S (w0[0]);
  t0[1] = hc_swap32_S (w0[1]);
  t0[2] = hc_swap32_S (w0[2]);
  t0[3] = hc_swap32_S (w0[3]);
  t1[0] = hc_swap32_S (w1[0]);
  t1[1] = hc_swap32_S (w1[1]);
  t1[2] = hc_swap32_S (w1[2]);
  t1[3] = hc_swap32_S (w1[3]);
  t2[0] = hc_swap32_S (w2[0]);
  t2[1] = hc_swap32_S (w2[1]);
  t2[2] = hc_swap32_S (w2[2]);
  t2[3] = hc_swap32_S (w2[3]);
  t3[0] = hc_swap32_S (w3[0]);
  t3[1] = hc_swap32_S (w3[1]);
  t3[2] = hc_swap32_S (w3[2]);
  t3[3] = hc_swap32_S (w3[3]);

  sha256_transform (t0, t1, t2, t3, digest);
}

DECLSPEC void orig_sha384_transform (PRIVATE_AS const u64 *w0, PRIVATE_AS const u64 *w1, PRIVATE_AS const u64 *w2, PRIVATE_AS const u64 *w3, PRIVATE_AS u64 *digest)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  t0[0] = hc_swap32_S (l32_from_64_S (w0[0]));
  t0[1] = hc_swap32_S (h32_from_64_S (w0[0]));
  t0[2] = hc_swap32_S (l32_from_64_S (w0[1]));
  t0[3] = hc_swap32_S (h32_from_64_S (w0[1]));
  t1[0] = hc_swap32_S (l32_from_64_S (w0[2]));
  t1[1] = hc_swap32_S (h32_from_64_S (w0[2]));
  t1[2] = hc_swap32_S (l32_from_64_S (w0[3]));
  t1[3] = hc_swap32_S (h32_from_64_S (w0[3]));
  t2[0] = hc_swap32_S (l32_from_64_S (w1[0]));
  t2[1] = hc_swap32_S (h32_from_64_S (w1[0]));
  t2[2] = hc_swap32_S (l32_from_64_S (w1[1]));
  t2[3] = hc_swap32_S (h32_from_64_S (w1[1]));
  t3[0] = hc_swap32_S (l32_from_64_S (w1[2]));
  t3[1] = hc_swap32_S (h32_from_64_S (w1[2]));
  t3[2] = hc_swap32_S (l32_from_64_S (w1[3]));
  t3[3] = hc_swap32_S (h32_from_64_S (w1[3]));
  t4[0] = hc_swap32_S (l32_from_64_S (w2[0]));
  t4[1] = hc_swap32_S (h32_from_64_S (w2[0]));
  t4[2] = hc_swap32_S (l32_from_64_S (w2[1]));
  t4[3] = hc_swap32_S (h32_from_64_S (w2[1]));
  t5[0] = hc_swap32_S (l32_from_64_S (w2[2]));
  t5[1] = hc_swap32_S (h32_from_64_S (w2[2]));
  t5[2] = hc_swap32_S (l32_from_64_S (w2[3]));
  t5[3] = hc_swap32_S (h32_from_64_S (w2[3]));
  t6[0] = hc_swap32_S (l32_from_64_S (w3[0]));
  t6[1] = hc_swap32_S (h32_from_64_S (w3[0]));
  t6[2] = hc_swap32_S (l32_from_64_S (w3[1]));
  t6[3] = hc_swap32_S (h32_from_64_S (w3[1]));
  t7[0] = hc_swap32_S (l32_from_64_S (w3[2]));
  t7[1] = hc_swap32_S (h32_from_64_S (w3[2]));
  t7[2] = hc_swap32_S (l32_from_64_S (w3[3]));
  t7[3] = hc_swap32_S (h32_from_64_S (w3[3]));

  sha384_transform (t0, t1, t2, t3, t4, t5, t6, t7, digest);
}

DECLSPEC void orig_sha512_transform (PRIVATE_AS const u64 *w0, PRIVATE_AS const u64 *w1, PRIVATE_AS const u64 *w2, PRIVATE_AS const u64 *w3, PRIVATE_AS u64 *digest)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  t0[0] = hc_swap32_S (l32_from_64_S (w0[0]));
  t0[1] = hc_swap32_S (h32_from_64_S (w0[0]));
  t0[2] = hc_swap32_S (l32_from_64_S (w0[1]));
  t0[3] = hc_swap32_S (h32_from_64_S (w0[1]));
  t1[0] = hc_swap32_S (l32_from_64_S (w0[2]));
  t1[1] = hc_swap32_S (h32_from_64_S (w0[2]));
  t1[2] = hc_swap32_S (l32_from_64_S (w0[3]));
  t1[3] = hc_swap32_S (h32_from_64_S (w0[3]));
  t2[0] = hc_swap32_S (l32_from_64_S (w1[0]));
  t2[1] = hc_swap32_S (h32_from_64_S (w1[0]));
  t2[2] = hc_swap32_S (l32_from_64_S (w1[1]));
  t2[3] = hc_swap32_S (h32_from_64_S (w1[1]));
  t3[0] = hc_swap32_S (l32_from_64_S (w1[2]));
  t3[1] = hc_swap32_S (h32_from_64_S (w1[2]));
  t3[2] = hc_swap32_S (l32_from_64_S (w1[3]));
  t3[3] = hc_swap32_S (h32_from_64_S (w1[3]));
  t4[0] = hc_swap32_S (l32_from_64_S (w2[0]));
  t4[1] = hc_swap32_S (h32_from_64_S (w2[0]));
  t4[2] = hc_swap32_S (l32_from_64_S (w2[1]));
  t4[3] = hc_swap32_S (h32_from_64_S (w2[1]));
  t5[0] = hc_swap32_S (l32_from_64_S (w2[2]));
  t5[1] = hc_swap32_S (h32_from_64_S (w2[2]));
  t5[2] = hc_swap32_S (l32_from_64_S (w2[3]));
  t5[3] = hc_swap32_S (h32_from_64_S (w2[3]));
  t6[0] = hc_swap32_S (l32_from_64_S (w3[0]));
  t6[1] = hc_swap32_S (h32_from_64_S (w3[0]));
  t6[2] = hc_swap32_S (l32_from_64_S (w3[1]));
  t6[3] = hc_swap32_S (h32_from_64_S (w3[1]));
  t7[0] = hc_swap32_S (l32_from_64_S (w3[2]));
  t7[1] = hc_swap32_S (h32_from_64_S (w3[2]));
  t7[2] = hc_swap32_S (l32_from_64_S (w3[3]));
  t7[3] = hc_swap32_S (h32_from_64_S (w3[3]));

  sha512_transform (t0, t1, t2, t3, t4, t5, t6, t7, digest);
}

#define AESSZ       16        // AES_BLOCK_SIZE

#define BLSZ256     32
#define BLSZ384     48
#define BLSZ512     64

#define WORDSZ256   64
#define WORDSZ384   128
#define WORDSZ512   128

#define PWMAXSZ     32        // hashcat password length limit
#define BLMAXSZ     BLSZ512
#define WORDMAXSZ   WORDSZ512

#define PWMAXSZ4    (PWMAXSZ    / 4)
#define BLMAXSZ4    (BLMAXSZ    / 4)
#define WORDMAXSZ4  (WORDMAXSZ  / 4)
#define AESSZ4      (AESSZ      / 4)

DECLSPEC void make_sc (LOCAL_AS u32 *sc, PRIVATE_AS const u32 *pw, const u32 pw_len, PRIVATE_AS const u32 *bl, const u32 bl_len)
{
  const u32 bd = bl_len / 4;

  const u32 pm = pw_len % 4;
  const u32 pd = pw_len / 4;

  u32 idx = 0;

  if (pm == 0)
  {
    for (u32 i = 0; i < pd; i++) sc[idx++] = pw[i];
    for (u32 i = 0; i < bd; i++) sc[idx++] = bl[i];
    for (u32 i = 0; i <  4; i++) sc[idx++] = sc[i];
  }
  else
  {
    u32 pm4 = 4 - pm;

    u32 i;

    #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
    for (i = 0; i < pd; i++) sc[idx++] = pw[i];
                             sc[idx++] = pw[i]
                                       | hc_bytealign_be (bl[0],         0, pm4);
    for (i = 1; i < bd; i++) sc[idx++] = hc_bytealign_be (bl[i], bl[i - 1], pm4);
                             sc[idx++] = hc_bytealign_be (sc[0], bl[i - 1], pm4);
    for (i = 1; i <  4; i++) sc[idx++] = hc_bytealign_be (sc[i], sc[i - 1], pm4);
                             sc[idx++] = hc_bytealign_be (    0, sc[i - 1], pm4);
    #endif

    #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

    #if defined IS_NV
    const int selector = (0x76543210 >> ((pm4 & 3) * 4)) & 0xffff;
    #endif

    #if (defined IS_AMD || defined IS_HIP)
    const int selector = l32_from_64_S (0x0706050403020100UL >> ((pm4 & 3) * 8));
    #endif

    for (i = 0; i < pd; i++) sc[idx++] = pw[i];
                             sc[idx++] = pw[i]
                                       | hc_byte_perm (        0, bl[0], selector);
    for (i = 1; i < bd; i++) sc[idx++] = hc_byte_perm (bl[i - 1], bl[i], selector);
                             sc[idx++] = hc_byte_perm (bl[i - 1], sc[0], selector);
    for (i = 1; i <  4; i++) sc[idx++] = hc_byte_perm (sc[i - 1], sc[i], selector);
                             sc[idx++] = hc_byte_perm (sc[i - 1],     0, selector);
    #endif
  }
}

DECLSPEC void make_pt_with_offset (PRIVATE_AS u32 *pt, const u32 offset, LOCAL_AS const u32 *sc, const u32 pwbl_len)
{
  const u32 m = offset % pwbl_len;

  const u32 om = m % 4;
  const u32 od = m / 4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  pt[0] = hc_bytealign_be (sc[od + 1], sc[od + 0], om);
  pt[1] = hc_bytealign_be (sc[od + 2], sc[od + 1], om);
  pt[2] = hc_bytealign_be (sc[od + 3], sc[od + 2], om);
  pt[3] = hc_bytealign_be (sc[od + 4], sc[od + 3], om);
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((om & 3) * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> ((om & 3) * 8));
  #endif
  pt[0] = hc_byte_perm (sc[od + 0], sc[od + 1], selector);
  pt[1] = hc_byte_perm (sc[od + 1], sc[od + 2], selector);
  pt[2] = hc_byte_perm (sc[od + 2], sc[od + 3], selector);
  pt[3] = hc_byte_perm (sc[od + 3], sc[od + 4], selector);
  #endif
}

DECLSPEC void make_w_with_offset (PRIVATE_AS ctx_t *ctx, const u32 W_len, const u32 offset, LOCAL_AS const u32 *sc, const u32 pwbl_len, PRIVATE_AS u32 *iv, PRIVATE_AS const u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  for (u32 k = 0, wk = 0; k < W_len; k += AESSZ, wk += AESSZ4)
  {
    u32 pt[AESSZ4];

    make_pt_with_offset (pt, offset + k, sc, pwbl_len);

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];
    pt[2] ^= iv[2];
    pt[3] ^= iv[3];

    aes128_encrypt (ks, pt, iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctx->W32[wk + 0] = iv[0];
    ctx->W32[wk + 1] = iv[1];
    ctx->W32[wk + 2] = iv[2];
    ctx->W32[wk + 3] = iv[3];
  }
}

DECLSPEC HC_INLINE u32 do_round (LOCAL_AS u32 *sc, PRIVATE_AS const u32 *pw, const u32 pw_len, PRIVATE_AS ctx_t *ctx, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  // make scratch buffer

  make_sc (sc, pw, pw_len, ctx->dgst32, ctx->dgst_len);

  // make sure pwbl_len is calculcated before it gets changed

  const u32 pwbl_len = pw_len + ctx->dgst_len;

  // init iv

  u32 iv[AESSZ4];

  iv[0] = ctx->dgst32[4];
  iv[1] = ctx->dgst32[5];
  iv[2] = ctx->dgst32[6];
  iv[3] = ctx->dgst32[7];

  // init aes

  u32 ks[44];

  aes128_set_encrypt_key (ks, ctx->dgst32, s_te0, s_te1, s_te2, s_te3);

  // first call is special as the hash depends on the result of it
  // but since we do not know about the outcome at this time
  // we must use the max

  make_w_with_offset (ctx, WORDMAXSZ, 0, sc, pwbl_len, iv, ks, s_te0, s_te1, s_te2, s_te3, s_te4);

  // now we can find out hash to use

  u32 sum = 0;

  for (u32 i = 0; i < 4; i++)
  {
    sum += (ctx->W32[i] >> 24) & 0xff;
    sum += (ctx->W32[i] >> 16) & 0xff;
    sum += (ctx->W32[i] >>  8) & 0xff;
    sum += (ctx->W32[i] >>  0) & 0xff;
  }

  // init hash

  switch (sum % 3)
  {
    case 0: ctx->dgst32[0] = SHA256M_A;
            ctx->dgst32[1] = SHA256M_B;
            ctx->dgst32[2] = SHA256M_C;
            ctx->dgst32[3] = SHA256M_D;
            ctx->dgst32[4] = SHA256M_E;
            ctx->dgst32[5] = SHA256M_F;
            ctx->dgst32[6] = SHA256M_G;
            ctx->dgst32[7] = SHA256M_H;
            ctx->dgst_len  = BLSZ256;
            ctx->W_len     = WORDSZ256;
            orig_sha256_transform (&ctx->W32[ 0], &ctx->W32[ 4], &ctx->W32[ 8], &ctx->W32[12], ctx->dgst32);
            orig_sha256_transform (&ctx->W32[16], &ctx->W32[20], &ctx->W32[24], &ctx->W32[28], ctx->dgst32);
            break;
    case 1: ctx->dgst64[0] = SHA384M_A;
            ctx->dgst64[1] = SHA384M_B;
            ctx->dgst64[2] = SHA384M_C;
            ctx->dgst64[3] = SHA384M_D;
            ctx->dgst64[4] = SHA384M_E;
            ctx->dgst64[5] = SHA384M_F;
            ctx->dgst64[6] = SHA384M_G;
            ctx->dgst64[7] = SHA384M_H;
            ctx->dgst_len  = BLSZ384;
            ctx->W_len     = WORDSZ384;
            orig_sha384_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
            break;
    case 2: ctx->dgst64[0] = SHA512M_A;
            ctx->dgst64[1] = SHA512M_B;
            ctx->dgst64[2] = SHA512M_C;
            ctx->dgst64[3] = SHA512M_D;
            ctx->dgst64[4] = SHA512M_E;
            ctx->dgst64[5] = SHA512M_F;
            ctx->dgst64[6] = SHA512M_G;
            ctx->dgst64[7] = SHA512M_H;
            ctx->dgst_len  = BLSZ512;
            ctx->W_len     = WORDSZ512;
            orig_sha512_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
            break;
  }

  // main loop

  const u32 final_len = pwbl_len * 64;

  const u32 iter_max = ctx->W_len - (ctx->W_len / 8);

  u32 offset;
  u32 left;

  for (offset = WORDMAXSZ, left = final_len - offset; left >= iter_max; offset += ctx->W_len, left -= ctx->W_len)
  {
    make_w_with_offset (ctx, ctx->W_len, offset, sc, pwbl_len, iv, ks, s_te0, s_te1, s_te2, s_te3, s_te4);

    switch (ctx->dgst_len)
    {
      case BLSZ256: orig_sha256_transform (&ctx->W32[ 0], &ctx->W32[ 4], &ctx->W32[ 8], &ctx->W32[12], ctx->dgst32);
                    break;
      case BLSZ384: orig_sha384_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
                    break;
      case BLSZ512: orig_sha512_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
                    break;
    }
  }

  u32 ex = 0;

  if (left)
  {
    switch (ctx->dgst_len)
    {
      case BLSZ384: make_w_with_offset (ctx, 64, offset, sc, pwbl_len, iv, ks, s_te0, s_te1, s_te2, s_te3, s_te4);
                    ctx->W64[ 8] = 0x80;
                    ctx->W64[ 9] = 0;
                    ctx->W64[10] = 0;
                    ctx->W64[11] = 0;
                    ctx->W64[12] = 0;
                    ctx->W64[13] = 0;
                    ctx->W64[14] = 0;
                    ctx->W64[15] = hc_swap64_S ((u64) (final_len * 8));
                    ex = ctx->W64[7] >> 56;
                    break;
      case BLSZ512: make_w_with_offset (ctx, 64, offset, sc, pwbl_len, iv, ks, s_te0, s_te1, s_te2, s_te3, s_te4);
                    ctx->W64[ 8] = 0x80;
                    ctx->W64[ 9] = 0;
                    ctx->W64[10] = 0;
                    ctx->W64[11] = 0;
                    ctx->W64[12] = 0;
                    ctx->W64[13] = 0;
                    ctx->W64[14] = 0;
                    ctx->W64[15] = hc_swap64_S ((u64) (final_len * 8));
                    ex = ctx->W64[7] >> 56;
                    break;
    }
  }
  else
  {
    switch (ctx->dgst_len)
    {
      case BLSZ256: ex = ctx->W32[15] >> 24;
                    ctx->W32[ 0] = 0x80;
                    ctx->W32[ 1] = 0;
                    ctx->W32[ 2] = 0;
                    ctx->W32[ 3] = 0;
                    ctx->W32[ 4] = 0;
                    ctx->W32[ 5] = 0;
                    ctx->W32[ 6] = 0;
                    ctx->W32[ 7] = 0;
                    ctx->W32[ 8] = 0;
                    ctx->W32[ 9] = 0;
                    ctx->W32[10] = 0;
                    ctx->W32[11] = 0;
                    ctx->W32[12] = 0;
                    ctx->W32[13] = 0;
                    ctx->W32[14] = 0;
                    ctx->W32[15] = hc_swap32_S (final_len * 8);
                    break;
      case BLSZ384: ex = ctx->W64[15] >> 56;
                    ctx->W64[ 0] = 0x80;
                    ctx->W64[ 1] = 0;
                    ctx->W64[ 2] = 0;
                    ctx->W64[ 3] = 0;
                    ctx->W64[ 4] = 0;
                    ctx->W64[ 5] = 0;
                    ctx->W64[ 6] = 0;
                    ctx->W64[ 7] = 0;
                    ctx->W64[ 8] = 0;
                    ctx->W64[ 9] = 0;
                    ctx->W64[10] = 0;
                    ctx->W64[11] = 0;
                    ctx->W64[12] = 0;
                    ctx->W64[13] = 0;
                    ctx->W64[14] = 0;
                    ctx->W64[15] = hc_swap64_S ((u64) (final_len * 8));
                    break;
      case BLSZ512: ex = ctx->W64[15] >> 56;
                    ctx->W64[ 0] = 0x80;
                    ctx->W64[ 1] = 0;
                    ctx->W64[ 2] = 0;
                    ctx->W64[ 3] = 0;
                    ctx->W64[ 4] = 0;
                    ctx->W64[ 5] = 0;
                    ctx->W64[ 6] = 0;
                    ctx->W64[ 7] = 0;
                    ctx->W64[ 8] = 0;
                    ctx->W64[ 9] = 0;
                    ctx->W64[10] = 0;
                    ctx->W64[11] = 0;
                    ctx->W64[12] = 0;
                    ctx->W64[13] = 0;
                    ctx->W64[14] = 0;
                    ctx->W64[15] = hc_swap64_S ((u64) (final_len * 8));
                    break;
    }
  }

  switch (ctx->dgst_len)
  {
    case BLSZ256: orig_sha256_transform (&ctx->W32[ 0], &ctx->W32[ 4], &ctx->W32[ 8], &ctx->W32[12], ctx->dgst32);
                  ctx->dgst32[ 0] = hc_swap32_S (ctx->dgst32[0]);
                  ctx->dgst32[ 1] = hc_swap32_S (ctx->dgst32[1]);
                  ctx->dgst32[ 2] = hc_swap32_S (ctx->dgst32[2]);
                  ctx->dgst32[ 3] = hc_swap32_S (ctx->dgst32[3]);
                  ctx->dgst32[ 4] = hc_swap32_S (ctx->dgst32[4]);
                  ctx->dgst32[ 5] = hc_swap32_S (ctx->dgst32[5]);
                  ctx->dgst32[ 6] = hc_swap32_S (ctx->dgst32[6]);
                  ctx->dgst32[ 7] = hc_swap32_S (ctx->dgst32[7]);
                  ctx->dgst32[ 8] = 0;
                  ctx->dgst32[ 9] = 0;
                  ctx->dgst32[10] = 0;
                  ctx->dgst32[11] = 0;
                  ctx->dgst32[12] = 0;
                  ctx->dgst32[13] = 0;
                  ctx->dgst32[14] = 0;
                  ctx->dgst32[15] = 0;
                  break;
    case BLSZ384: orig_sha384_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
                  ctx->dgst64[0] = hc_swap64_S (ctx->dgst64[0]);
                  ctx->dgst64[1] = hc_swap64_S (ctx->dgst64[1]);
                  ctx->dgst64[2] = hc_swap64_S (ctx->dgst64[2]);
                  ctx->dgst64[3] = hc_swap64_S (ctx->dgst64[3]);
                  ctx->dgst64[4] = hc_swap64_S (ctx->dgst64[4]);
                  ctx->dgst64[5] = hc_swap64_S (ctx->dgst64[5]);
                  ctx->dgst64[6] = 0;
                  ctx->dgst64[7] = 0;
                  break;
    case BLSZ512: orig_sha512_transform (&ctx->W64[ 0], &ctx->W64[ 4], &ctx->W64[ 8], &ctx->W64[12], ctx->dgst64);
                  ctx->dgst64[0] = hc_swap64_S (ctx->dgst64[0]);
                  ctx->dgst64[1] = hc_swap64_S (ctx->dgst64[1]);
                  ctx->dgst64[2] = hc_swap64_S (ctx->dgst64[2]);
                  ctx->dgst64[3] = hc_swap64_S (ctx->dgst64[3]);
                  ctx->dgst64[4] = hc_swap64_S (ctx->dgst64[4]);
                  ctx->dgst64[5] = hc_swap64_S (ctx->dgst64[5]);
                  ctx->dgst64[6] = hc_swap64_S (ctx->dgst64[6]);
                  ctx->dgst64[7] = hc_swap64_S (ctx->dgst64[7]);
                  break;
  }

  return ex;
}

KERNEL_FQ void m10700_init (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha256_update_global_swap (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  sha256_final (&ctx);

  tmps[gid].dgst32[0] = hc_swap32_S (ctx.h[0]);
  tmps[gid].dgst32[1] = hc_swap32_S (ctx.h[1]);
  tmps[gid].dgst32[2] = hc_swap32_S (ctx.h[2]);
  tmps[gid].dgst32[3] = hc_swap32_S (ctx.h[3]);
  tmps[gid].dgst32[4] = hc_swap32_S (ctx.h[4]);
  tmps[gid].dgst32[5] = hc_swap32_S (ctx.h[5]);
  tmps[gid].dgst32[6] = hc_swap32_S (ctx.h[6]);
  tmps[gid].dgst32[7] = hc_swap32_S (ctx.h[7]);
  tmps[gid].dgst_len  = BLSZ256;
  tmps[gid].W_len     = WORDSZ256;
}

KERNEL_FQ void m10700_loop (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len & 31;

  if (pw_len == 0) return;

  /**
   * digest
   */

  ctx_t ctx;

  ctx.dgst64[0] = tmps[gid].dgst64[0];
  ctx.dgst64[1] = tmps[gid].dgst64[1];
  ctx.dgst64[2] = tmps[gid].dgst64[2];
  ctx.dgst64[3] = tmps[gid].dgst64[3];
  ctx.dgst64[4] = tmps[gid].dgst64[4];
  ctx.dgst64[5] = tmps[gid].dgst64[5];
  ctx.dgst64[6] = tmps[gid].dgst64[6];
  ctx.dgst64[7] = tmps[gid].dgst64[7];
  ctx.dgst_len  = tmps[gid].dgst_len;
  ctx.W_len     = tmps[gid].W_len;

  LOCAL_VK u32 s_sc[256][PWMAXSZ4 + BLMAXSZ4 + AESSZ4];

  u32 ex = 0;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    ex = do_round (s_sc[lid], w0, pw_len, &ctx, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  if ((LOOP_POS + LOOP_CNT) == 64)
  {
    for (u32 i = 64; i < (ex & 0xff) + 32; i++)
    {
      ex = do_round (s_sc[lid], w0, pw_len, &ctx, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
  }

  tmps[gid].dgst64[0] = ctx.dgst64[0];
  tmps[gid].dgst64[1] = ctx.dgst64[1];
  tmps[gid].dgst64[2] = ctx.dgst64[2];
  tmps[gid].dgst64[3] = ctx.dgst64[3];
  tmps[gid].dgst64[4] = ctx.dgst64[4];
  tmps[gid].dgst64[5] = ctx.dgst64[5];
  tmps[gid].dgst64[6] = ctx.dgst64[6];
  tmps[gid].dgst64[7] = ctx.dgst64[7];
  tmps[gid].dgst_len  = ctx.dgst_len;
  tmps[gid].W_len     = ctx.W_len;
}

KERNEL_FQ void m10700_comp (KERN_ATTR_TMPS_ESALT (pdf17l8_tmp_t, pdf_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = hc_swap32_S (tmps[gid].dgst32[DGST_R0]);
  const u32 r1 = hc_swap32_S (tmps[gid].dgst32[DGST_R1]);
  const u32 r2 = hc_swap32_S (tmps[gid].dgst32[DGST_R2]);
  const u32 r3 = hc_swap32_S (tmps[gid].dgst32[DGST_R3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
