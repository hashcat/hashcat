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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_bignum_2048.cl)
#include M2S(INCLUDE_PATH/inc_radmin3_constants.h)
#endif

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN];

} radmin3_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (radmin3_t)

typedef struct pcfg_hash_ctx
{
  sha1_ctx_t ctx0;
  sha1_ctx_t ctx1;
  GLOBAL_AS const radmin3_t *esalt_bufs;
  u32 digest_pos;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const radmin3_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;

  sha1_init (&hc->ctx0);

  sha1_update_global (&hc->ctx0, esalt_bufs[digest_pos].user, esalt_bufs[digest_pos].user_len);

  sha1_init (&hc->ctx1);

  sha1_update_global (&hc->ctx1, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  sha1_ctx_t c0 = hc->ctx0;

  sha1_update_utf16le_swap (&c0, w, len);

  sha1_final (&c0);

  sha1_ctx_t c1 = hc->ctx1;

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = c0.h[0];
  w0[1] = c0.h[1];
  w0[2] = c0.h[2];
  w0[3] = c0.h[3];
  w1[0] = c0.h[4];

  sha1_update_64 (&c1, w0, w1, w2, w3, 20);

  sha1_final (&c1);

  const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

  PRIVATE_AS const u32 m[64] =
  {
    RADMIN3_M[  0], RADMIN3_M[  1], RADMIN3_M[  2], RADMIN3_M[  3],
    RADMIN3_M[  4], RADMIN3_M[  5], RADMIN3_M[  6], RADMIN3_M[  7],
    RADMIN3_M[  8], RADMIN3_M[  9], RADMIN3_M[ 10], RADMIN3_M[ 11],
    RADMIN3_M[ 12], RADMIN3_M[ 13], RADMIN3_M[ 14], RADMIN3_M[ 15],
    RADMIN3_M[ 16], RADMIN3_M[ 17], RADMIN3_M[ 18], RADMIN3_M[ 19],
    RADMIN3_M[ 20], RADMIN3_M[ 21], RADMIN3_M[ 22], RADMIN3_M[ 23],
    RADMIN3_M[ 24], RADMIN3_M[ 25], RADMIN3_M[ 26], RADMIN3_M[ 27],
    RADMIN3_M[ 28], RADMIN3_M[ 29], RADMIN3_M[ 30], RADMIN3_M[ 31],
    RADMIN3_M[ 32], RADMIN3_M[ 33], RADMIN3_M[ 34], RADMIN3_M[ 35],
    RADMIN3_M[ 36], RADMIN3_M[ 37], RADMIN3_M[ 38], RADMIN3_M[ 39],
    RADMIN3_M[ 40], RADMIN3_M[ 41], RADMIN3_M[ 42], RADMIN3_M[ 43],
    RADMIN3_M[ 44], RADMIN3_M[ 45], RADMIN3_M[ 46], RADMIN3_M[ 47],
    RADMIN3_M[ 48], RADMIN3_M[ 49], RADMIN3_M[ 50], RADMIN3_M[ 51],
    RADMIN3_M[ 52], RADMIN3_M[ 53], RADMIN3_M[ 54], RADMIN3_M[ 55],
    RADMIN3_M[ 56], RADMIN3_M[ 57], RADMIN3_M[ 58], RADMIN3_M[ 59],
    RADMIN3_M[ 60], RADMIN3_M[ 61], RADMIN3_M[ 62], RADMIN3_M[ 63],
  };

  u32 r_t[64] =
  {
    RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
    RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
    RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
    RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
    RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
    RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
    RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
    RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
    RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
    RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
    RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
    RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
    RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
    RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
    RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
    RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
  };

  for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
  {
    const u32 div   = (PRECOMP_BITS * i) / 32;
    const u32 shift = (PRECOMP_BITS * i) % 32;

    u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK;

    if (32 - shift < PRECOMP_BITS)
    {
      cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
    }

    if (cur_sel == 0) continue;

    const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN;

    const u32 pre[64] =
    {
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  0],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  1],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  2],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  3],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  4],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  5],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  6],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  7],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  8],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  9],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 10],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 11],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 12],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 13],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 14],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 15],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 16],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 17],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 18],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 19],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 20],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 21],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 22],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 23],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 24],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 25],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 26],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 27],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 28],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 29],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 30],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 31],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 32],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 33],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 34],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 35],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 36],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 37],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 38],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 39],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 40],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 41],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 42],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 43],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 44],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 45],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 46],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 47],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 48],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 49],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 50],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 51],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 52],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 53],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 54],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 55],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 56],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 57],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 58],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 59],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 60],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 61],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 62],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 63],
    };

    bn2048_mont_mul (r_t, r_t, pre, m, RADMIN3_N0);
  }

  dgst[0] = r_t[0];
  dgst[1] = r_t[1];
  dgst[2] = r_t[2];
  dgst[3] = r_t[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{

  sha1_ctx_t c0 = hc->ctx0;

  sha1_update_global_utf16le_swap (&c0, w, len);

  sha1_final (&c0);

  sha1_ctx_t c1 = hc->ctx1;

  u32 w0[4] = { 0 };
  u32 w1[4] = { 0 };
  u32 w2[4] = { 0 };
  u32 w3[4] = { 0 };

  w0[0] = c0.h[0];
  w0[1] = c0.h[1];
  w0[2] = c0.h[2];
  w0[3] = c0.h[3];
  w1[0] = c0.h[4];

  sha1_update_64 (&c1, w0, w1, w2, w3, 20);

  sha1_final (&c1);

  const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

  PRIVATE_AS const u32 m[64] =
  {
    RADMIN3_M[  0], RADMIN3_M[  1], RADMIN3_M[  2], RADMIN3_M[  3],
    RADMIN3_M[  4], RADMIN3_M[  5], RADMIN3_M[  6], RADMIN3_M[  7],
    RADMIN3_M[  8], RADMIN3_M[  9], RADMIN3_M[ 10], RADMIN3_M[ 11],
    RADMIN3_M[ 12], RADMIN3_M[ 13], RADMIN3_M[ 14], RADMIN3_M[ 15],
    RADMIN3_M[ 16], RADMIN3_M[ 17], RADMIN3_M[ 18], RADMIN3_M[ 19],
    RADMIN3_M[ 20], RADMIN3_M[ 21], RADMIN3_M[ 22], RADMIN3_M[ 23],
    RADMIN3_M[ 24], RADMIN3_M[ 25], RADMIN3_M[ 26], RADMIN3_M[ 27],
    RADMIN3_M[ 28], RADMIN3_M[ 29], RADMIN3_M[ 30], RADMIN3_M[ 31],
    RADMIN3_M[ 32], RADMIN3_M[ 33], RADMIN3_M[ 34], RADMIN3_M[ 35],
    RADMIN3_M[ 36], RADMIN3_M[ 37], RADMIN3_M[ 38], RADMIN3_M[ 39],
    RADMIN3_M[ 40], RADMIN3_M[ 41], RADMIN3_M[ 42], RADMIN3_M[ 43],
    RADMIN3_M[ 44], RADMIN3_M[ 45], RADMIN3_M[ 46], RADMIN3_M[ 47],
    RADMIN3_M[ 48], RADMIN3_M[ 49], RADMIN3_M[ 50], RADMIN3_M[ 51],
    RADMIN3_M[ 52], RADMIN3_M[ 53], RADMIN3_M[ 54], RADMIN3_M[ 55],
    RADMIN3_M[ 56], RADMIN3_M[ 57], RADMIN3_M[ 58], RADMIN3_M[ 59],
    RADMIN3_M[ 60], RADMIN3_M[ 61], RADMIN3_M[ 62], RADMIN3_M[ 63],
  };

  u32 r_t[64] =
  {
    RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
    RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
    RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
    RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
    RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
    RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
    RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
    RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
    RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
    RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
    RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
    RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
    RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
    RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
    RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
    RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
  };

  for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
  {
    const u32 div   = (PRECOMP_BITS * i) / 32;
    const u32 shift = (PRECOMP_BITS * i) % 32;

    u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK;

    if (32 - shift < PRECOMP_BITS)
    {
      cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
    }

    if (cur_sel == 0) continue;

    const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN;

    const u32 pre[64] =
    {
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  0],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  1],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  2],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  3],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  4],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  5],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  6],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  7],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  8],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx +  9],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 10],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 11],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 12],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 13],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 14],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 15],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 16],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 17],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 18],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 19],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 20],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 21],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 22],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 23],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 24],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 25],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 26],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 27],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 28],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 29],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 30],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 31],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 32],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 33],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 34],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 35],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 36],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 37],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 38],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 39],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 40],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 41],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 42],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 43],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 44],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 45],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 46],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 47],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 48],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 49],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 50],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 51],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 52],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 53],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 54],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 55],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 56],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 57],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 58],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 59],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 60],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 61],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 62],
      hc->esalt_bufs[hc->digest_pos].pre[pre_idx + 63],
    };

    bn2048_mont_mul (r_t, r_t, pre, m, RADMIN3_N0);
  }

  dgst[0] = r_t[0];
  dgst[1] = r_t[1];
  dgst[2] = r_t[2];
  dgst[3] = r_t[3];

  return true;
}

#define PCFG_KERNEL_MXX m29200_mxx
#define PCFG_KERNEL_SXX m29200_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
