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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

CONSTANT_VK u32a k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

DECLSPEC void sha256_transform_z (PRIVATE_AS u32 *digest)
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

  #define ROUND_STEP_Z(i)                                                                 \
  {                                                                                       \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, 0, k_sha256[i +  0]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, 0, k_sha256[i +  1]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, 0, k_sha256[i +  2]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, 0, k_sha256[i +  3]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, 0, k_sha256[i +  4]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, 0, k_sha256[i +  5]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, 0, k_sha256[i +  6]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, 0, k_sha256[i +  7]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, 0, k_sha256[i +  8]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, 0, k_sha256[i +  9]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, 0, k_sha256[i + 10]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, 0, k_sha256[i + 11]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, 0, k_sha256[i + 12]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, 0, k_sha256[i + 13]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, 0, k_sha256[i + 14]);  \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, 0, k_sha256[i + 15]);  \
  }

  ROUND_STEP_Z (0);

  #if defined IS_CUDA
  ROUND_STEP_Z (16);
  ROUND_STEP_Z (32);
  ROUND_STEP_Z (48);
  #else
  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_STEP_Z (i);
  }
  #endif

  #undef ROUND_STEP_Z

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

typedef struct pcfg_hash_ctx
{
  u32 w_s1[16];
  u32 w_s2[16];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 salt_buf0 = hc_swap32_S (salt_bufs[salt_pos].salt_buf[0]);
  const u32 salt_buf1 = hc_swap32_S (salt_bufs[salt_pos].salt_buf[1]);
  const u32 salt_buf2 = hc_swap32_S (salt_bufs[salt_pos].salt_buf[2]); // 0x80

  for (u32 i = 0; i < 16; i++)
  {
    hc->w_s1[i] = 0;
    hc->w_s2[i] = 0;
  }

  // the salt begins at byte 510, so its first two bytes end the eighth block

  hc->w_s1[15] = salt_buf0 >> 16;

  hc->w_s2[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
  hc->w_s2[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
  hc->w_s2[ 2] = salt_buf2 << 16;
  hc->w_s2[15] = (510 + 8) * 8;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_sybase_ase (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, PRIVATE_AS u32 *dgst)
{
  u32 w_t[16];

  for (u32 i = 0; i < 16; i++)
  {
    w_t[i] = (pcfg_get_byte (w, (i * 2) + 0) << 16) | pcfg_get_byte (w, (i * 2) + 1);
  }

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (&w_t[0], &w_t[4], &w_t[8], &w_t[12], digest);                      //   0 -  64
  sha256_transform_z (digest);                                                         //  64 - 128
  sha256_transform_z (digest);                                                         // 128 - 192
  sha256_transform_z (digest);                                                         // 192 - 256
  sha256_transform_z (digest);                                                         // 256 - 320
  sha256_transform_z (digest);                                                         // 320 - 384
  sha256_transform_z (digest);                                                         // 384 - 448
  sha256_transform (&hc->w_s1[0], &hc->w_s1[4], &hc->w_s1[8], &hc->w_s1[12], digest);  // 448 - 512
  sha256_transform (&hc->w_s2[0], &hc->w_s2[4], &hc->w_s2[8], &hc->w_s2[12], digest);  // 512 - 576

  // the four words m08000_m04 hands to COMPARE_M_SIMD, in its order

  dgst[0] = digest[3];
  dgst[1] = digest[7];
  dgst[2] = digest[2];
  dgst[3] = digest[6];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  return pcfg_sybase_ase (hc, w, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_sybase_ase (hc, t, dgst);
}

#define PCFG_KERNEL_MXX m08000_mxx
#define PCFG_KERNEL_SXX m08000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
