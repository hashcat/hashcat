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
#endif

typedef struct chacha20
{
  u32 iv[2];
  u32 plain[2];
  u32 position[2];
  u32 offset;

} chacha20_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (chacha20_t)

#define CHACHA_CONST_00 0x61707865
#define CHACHA_CONST_01 0x3320646e
#define CHACHA_CONST_02 0x79622d32
#define CHACHA_CONST_03 0x6b206574

#define QR(a, b, c, d)                    \
  do {                                    \
    x[a] = x[a] + x[b];                   \
    x[d] = hc_rotl32_S (x[d] ^ x[a], 16); \
    x[c] = x[c] + x[d];                   \
    x[b] = hc_rotl32_S (x[b] ^ x[c], 12); \
    x[a] = x[a] + x[b];                   \
    x[d] = hc_rotl32_S (x[d] ^ x[a], 8);  \
    x[c] = x[c] + x[d];                   \
    x[b] = hc_rotl32_S (x[b] ^ x[c], 7);  \
  } while (0);

typedef struct pcfg_hash_ctx
{
  u32 iv[2];
  u32 plain[2];
  u32 position[2];
  u32 offset;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const chacha20_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->position[0] = esalt_bufs[digest_pos].position[0];
  hc->position[1] = esalt_bufs[digest_pos].position[1];

  hc->offset = esalt_bufs[digest_pos].offset;

  hc->iv[0] = esalt_bufs[digest_pos].iv[0];
  hc->iv[1] = esalt_bufs[digest_pos].iv[1];

  hc->plain[0] = esalt_bufs[digest_pos].plain[0];
  hc->plain[1] = esalt_bufs[digest_pos].plain[1];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_chacha20 (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *key, PRIVATE_AS u32 *dgst)
{
  /**
   * Key expansion
   */

  u32 ctx[16];

  ctx[ 0] = CHACHA_CONST_00;
  ctx[ 1] = CHACHA_CONST_01;
  ctx[ 2] = CHACHA_CONST_02;
  ctx[ 3] = CHACHA_CONST_03;
  ctx[ 4] = key[0];
  ctx[ 5] = key[1];
  ctx[ 6] = key[2];
  ctx[ 7] = key[3];
  ctx[ 8] = key[4];
  ctx[ 9] = key[5];
  ctx[10] = key[6];
  ctx[11] = key[7];
  ctx[12] = hc->position[0];
  ctx[13] = hc->position[1];
  ctx[14] = hc->iv[1];
  ctx[15] = hc->iv[0];

  /**
   * Generate 64 byte keystream
   */

  u32 x[32];

  x[ 0] = ctx[ 0];
  x[ 1] = ctx[ 1];
  x[ 2] = ctx[ 2];
  x[ 3] = ctx[ 3];
  x[ 4] = ctx[ 4];
  x[ 5] = ctx[ 5];
  x[ 6] = ctx[ 6];
  x[ 7] = ctx[ 7];
  x[ 8] = ctx[ 8];
  x[ 9] = ctx[ 9];
  x[10] = ctx[10];
  x[11] = ctx[11];
  x[12] = ctx[12];
  x[13] = ctx[13];
  x[14] = ctx[14];
  x[15] = ctx[15];

  #pragma unroll
  for (u32 i = 0; i < 10; i++)
  {
    /* Column round */
    QR (0, 4, 8,  12);
    QR (1, 5, 9,  13);
    QR (2, 6, 10, 14);
    QR (3, 7, 11, 15);

    /* Diagonal round */
    QR (0, 5, 10, 15);
    QR (1, 6, 11, 12);
    QR (2, 7, 8,  13);
    QR (3, 4, 9,  14);
  }

  x[ 0] += ctx[ 0];
  x[ 1] += ctx[ 1];
  x[ 2] += ctx[ 2];
  x[ 3] += ctx[ 3];
  x[ 4] += ctx[ 4];
  x[ 5] += ctx[ 5];
  x[ 6] += ctx[ 6];
  x[ 7] += ctx[ 7];
  x[ 8] += ctx[ 8];
  x[ 9] += ctx[ 9];
  x[10] += ctx[10];
  x[11] += ctx[11];
  x[12] += ctx[12];
  x[13] += ctx[13];
  x[14] += ctx[14];
  x[15] += ctx[15];

  if (hc->offset > 56)
  {
    /**
     * Generate a second 64 byte keystream
     */

    ctx[12] += 1;

    if (ctx[12] == 0) ctx[13] += 1;

    x[16] = ctx[ 0];
    x[17] = ctx[ 1];
    x[18] = ctx[ 2];
    x[19] = ctx[ 3];
    x[20] = ctx[ 4];
    x[21] = ctx[ 5];
    x[22] = ctx[ 6];
    x[23] = ctx[ 7];
    x[24] = ctx[ 8];
    x[25] = ctx[ 9];
    x[26] = ctx[10];
    x[27] = ctx[11];
    x[28] = ctx[12];
    x[29] = ctx[13];
    x[30] = ctx[14];
    x[31] = ctx[15];

    #pragma unroll
    for (u32 i = 0; i < 10; i++)
    {
      /* Column round */
      QR (16, 20, 24, 28);
      QR (17, 21, 25, 29);
      QR (18, 22, 26, 30);
      QR (19, 23, 27, 31);

      /* Diagonal round */
      QR (16, 21, 26, 31);
      QR (17, 22, 27, 28);
      QR (18, 23, 24, 29);
      QR (19, 20, 25, 30);
    }

    x[16] += ctx[ 0];
    x[17] += ctx[ 1];
    x[18] += ctx[ 2];
    x[19] += ctx[ 3];
    x[20] += ctx[ 4];
    x[21] += ctx[ 5];
    x[22] += ctx[ 6];
    x[23] += ctx[ 7];
    x[24] += ctx[ 8];
    x[25] += ctx[ 9];
    x[26] += ctx[10];
    x[27] += ctx[11];
    x[28] += ctx[12];
    x[29] += ctx[13];
    x[30] += ctx[14];
    x[31] += ctx[15];
  }

  /**
   * Encrypt plaintext with keystream
   */

  const u32 index  = hc->offset / 4;
  const u32 remain = hc->offset % 4;

  dgst[0] = hc->plain[1];
  dgst[1] = hc->plain[0];
  dgst[2] = 0;
  dgst[3] = 0;

  if (remain > 0)
  {
    dgst[1] ^= x[index + 0] >> ( 0 + remain * 8);
    dgst[1] ^= x[index + 1] << (32 - remain * 8);

    dgst[0] ^= x[index + 1] >> ( 0 + remain * 8);
    dgst[0] ^= x[index + 2] << (32 - remain * 8);
  }
  else
  {
    dgst[1] ^= x[index + 0];
    dgst[0] ^= x[index + 1];
  }

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 32) return false;

  return pcfg_chacha20 (hc, w, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = w[i];

  return pcfg_chacha20 (hc, t, dgst);
}

#define PCFG_KERNEL_MXX m15400_mxx
#define PCFG_KERNEL_SXX m15400_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
