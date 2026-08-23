/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

DECLSPEC void pcfg_md5_16 (PRIVATE_AS const u32 *w, const u32 bits, PRIVATE_AS u32 *dgst)
{
  u32 w0[4] = { w[0], w[1], w[2], w[3] };
  u32 w1[4] = { 0, 0, 0, 0 };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, bits, 0 };

  dgst[0] = MD5M_A;
  dgst[1] = MD5M_B;
  dgst[2] = MD5M_C;
  dgst[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, dgst);
}

DECLSPEC void pcfg_md5_32 (PRIVATE_AS const u32 *w, const u32 bits, PRIVATE_AS u32 *dgst)
{
  u32 w0[4] = { w[0], w[1], w[ 2], w[ 3] };
  u32 w1[4] = { w[4], w[5], w[ 6], w[ 7] };
  u32 w2[4] = { 0, 0, 0, 0 };
  u32 w3[4] = { 0, 0, bits, 0 };

  dgst[0] = MD5M_A;
  dgst[1] = MD5M_B;
  dgst[2] = MD5M_C;
  dgst[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, dgst);
}

DECLSPEC void pcfg_md5_var (PRIVATE_AS const u32 *w, const u32 lenbits, const bool spill, PRIVATE_AS u32 *dgst)
{
  u32 w0[4] = { w[ 0], w[ 1], w[ 2], w[ 3] };
  u32 w1[4] = { w[ 4], w[ 5], w[ 6], w[ 7] };
  u32 w2[4] = { w[ 8], w[ 9], w[10], w[11] };
  u32 w3[4] = { w[12], w[13], w[14], w[15] };

  if (spill == false) w3[2] = lenbits;

  dgst[0] = MD5M_A;
  dgst[1] = MD5M_B;
  dgst[2] = MD5M_C;
  dgst[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, dgst);

  if (spill == true)
  {
    w0[0] = 0;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = lenbits;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, dgst);
  }
}

DECLSPEC void pcfg_md5 (PRIVATE_AS const u32 *w, MAYBE_UNUSED const u32 nblk, const u32 bits, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = w[ 0];
  w0[1] = w[ 1];
  w0[2] = w[ 2];
  w0[3] = w[ 3];
  w1[0] = w[ 4];
  w1[1] = w[ 5];
  w1[2] = w[ 6];
  w1[3] = w[ 7];
  w2[0] = w[ 8];
  w2[1] = w[ 9];
  w2[2] = w[10];
  w2[3] = w[11];
  w3[0] = w[12];
  w3[1] = w[13];
  w3[2] = w[14];
  w3[3] = w[15];

  dgst[0] = MD5M_A;
  dgst[1] = MD5M_B;
  dgst[2] = MD5M_C;
  dgst[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, dgst);

  #if PCFG_DEV_WORDS >= 32
  if (nblk > 1)
  {
    w0[0] = w[16];
    w0[1] = w[17];
    w0[2] = w[18];
    w0[3] = w[19];
    w1[0] = w[20];
    w1[1] = w[21];
    w1[2] = w[22];
    w1[3] = w[23];
    w2[0] = w[24];
    w2[1] = w[25];
    w2[2] = w[26];
    w2[3] = w[27];
    w3[0] = w[28];
    w3[1] = w[29];
    w3[2] = w[30];
    w3[3] = w[31];

    md5_transform (w0, w1, w2, w3, dgst);
  }
  #endif

  if (bits != 0)
  {
    w0[0] = 0;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = bits;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, dgst);
  }
}

typedef struct pcfg_hash_ctx
{
  #if (PCFG_DEV_WORDS == 16) && (PCFG_DEV_VARLEN == 0)

  u32 bits;
  u32 lenbits;

  #else

  u32 unused;

  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
  #if (PCFG_DEV_WORDS == 16) && (PCFG_DEV_VARLEN == 0)

  const bool spill = ((pw_len + 8) >= 64);

  w[pw_len / 4] |= 0x80u << ((pw_len & 3) * 8);

  if (spill == false) w[14] = pw_len * 8;

  hc->bits    = (spill == true) ? (pw_len * 8) : 0;
  hc->lenbits = pw_len * 8;

  #else

  hc->unused = 0;

  #endif
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 h[4];

  #if PCFG_DEV_WORDS == 16

  #if PCFG_DEV_VARLEN

  pcfg_put_byte (w, len, 0x80);

  const u32 lenbits = len * 8;

  if      (len < 16) pcfg_md5_16  (w, lenbits, h);
  else if (len < 32) pcfg_md5_32  (w, lenbits, h);
  else               pcfg_md5_var (w, lenbits, ((len + 8) >= 64), h);

  #else

  if      (len < 16) pcfg_md5_16 (w, hc->lenbits, h);
  else if (len < 32) pcfg_md5_32 (w, hc->lenbits, h);
  else               pcfg_md5    (w, 1, hc->bits, h);

  #endif

  #else

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update (&ctx, w, len);

  md5_final (&ctx);

  for (u32 i = 0; i < 4; i++) h[i] = ctx.h[i];

  #endif

  dgst[0] = h[DGST_R0];
  dgst[1] = h[DGST_R1];
  dgst[2] = h[DGST_R2];
  dgst[3] = h[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, w, len);

  md5_final (&ctx);

  dgst[0] = ctx.h[DGST_R0];
  dgst[1] = ctx.h[DGST_R1];
  dgst[2] = ctx.h[DGST_R2];
  dgst[3] = ctx.h[DGST_R3];

  return true;
}

#define PCFG_KERNEL_MXX m00000_mxx
#define PCFG_KERNEL_SXX m00000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
