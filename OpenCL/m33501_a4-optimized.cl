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
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct rc4
{
  u32 dropN;
  u32 ct_len;
  u32 pt_len;
  u32 pt_off;

  u32 pt[2];
  u32 ct[16];

} rc4_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (rc4_t)

CONSTANT_VK u32a pt_masks[12] =
{
  0x00000000,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0,
  0
};

#define PCFG_HASH_SHARED_DECL \
  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->S = S;                    \
  (hc)->lid = lid;

typedef struct pcfg_hash_ctx
{
  u32 ct[4];

  u32 dropN;
  u32 pt_len;

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const rc4_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->dropN  = esalt_bufs[digest_pos].dropN;
  hc->pt_len = esalt_bufs[digest_pos].pt_len;

  for (u32 i = 0; i < 4; i++) hc->ct[i] = esalt_bufs[digest_pos].ct[i];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_rc4_72 (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, PRIVATE_AS u32 *dgst)
{
  u32 key[3];

  key[0] = w[0];
  key[1] = w[1];
  key[2] = w[2] & 0xff;

  rc4_init_72 (hc->S, key, hc->lid);

  u8 i = 0;
  u8 j = 0;

  if (hc->dropN > 0)
  {
    rc4_dropN (hc->S, &i, &j, hc->dropN, hc->lid);
  }

  u32 out[4];

  rc4_next_16 (hc->S, i, j, hc->ct, out, hc->lid);

  const u32 pt_len = hc->pt_len;

  if (pt_len == 9)
  {
    out[2] &= pt_masks[1];
  }
  else
  {
    out[2] = 0;

    if (pt_len < 5)
    {
      out[1] = 0;

      if (pt_len >= 1 && pt_len <= 3)
      {
        out[0] &= pt_masks[pt_len];
      }
    }
    else if (pt_len <= 7)
    {
      out[1] &= pt_masks[pt_len];
    }
  }

  out[3] = 0;

  dgst[0] = out[0];
  dgst[1] = out[1];
  dgst[2] = out[2];
  dgst[3] = out[3];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 9) return false;

  return pcfg_rc4_72 (hc, w, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 9) return false;

  // Three words is the whole of what the key setup reads, and the copy is what lets it stay private.

  u32 t[3];

  t[0] = w[0];
  t[1] = w[1];
  t[2] = w[2];

  return pcfg_rc4_72 (hc, t, dgst);
}

#define PCFG_KERNEL_MXX m33501_mxx
#define PCFG_KERNEL_SXX m33501_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
