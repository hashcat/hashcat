/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

typedef struct iclass_state
{
  u16 t;
  u8  l;
  u8  r;
  u8  b;
} iclass_state_t;

DECLSPEC iclass_state_t iclass_successor (PRIVATE_AS const u8 *k, const iclass_state_t s, const u8 y)
{
  const u8 r0 = (s.r >> 7) & 1;
  const u8 r4 = (s.r >> 3) & 1;
  const u8 r7 =  s.r        & 1;

  const u8 Tt = (u8) (((s.t >> 15) & 1) ^ ((s.t >> 14) & 1)
             ^ ((s.t >> 10) & 1) ^ ((s.t >>  8) & 1)
             ^ ((s.t >>  5) & 1) ^ ((s.t >>  4) & 1)
             ^ ((s.t >>  1) & 1) ^ ( s.t        & 1));

  const u8 Bt = (u8) (((s.b >> 6) & 1) ^ ((s.b >> 5) & 1)
             ^ ((s.b >> 4) & 1) ^ ( s.b        & 1));

  iclass_state_t ns;

  ns.t = (u16) ((s.t >> 1) | ((u16) ((Tt ^ r0 ^ r4) & 1) << 15));
  ns.b = (u8)  ((s.b >> 1) | ((u8)  ((Bt ^ r7)      & 1) << 7));

  const u8 r1 = (s.r >> 6) & 1;
  const u8 r2 = (s.r >> 5) & 1;
  const u8 r3 = (s.r >> 4) & 1;
  const u8 r5 = (s.r >> 2) & 1;
  const u8 r6 = (s.r >> 1) & 1;

  const u8 z0 = (u8) ((r0 & r2) ^ (r1 & (r3 ^ 1)) ^ (r2 | r4));
  const u8 z1 = (u8) ((r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ Tt ^ y);
  const u8 z2 = (u8) ((r3 & (r5 ^ 1)) ^ (r4 & r6) ^ r7 ^ Tt);

  const u8 sel = ((z0 & 1) << 2) | ((z1 & 1) << 1) | (z2 & 1);
  const u8 val = (u8) (k[sel] ^ ns.b);

  ns.l = (u8) ((val + s.l + s.r) & 0xFF);
  ns.r = (u8) ((val + s.l)       & 0xFF);

  return ns;
}

DECLSPEC u8 reflect8 (u8 b)
{
  b = (u8) (((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
  b = (u8) (((b & 0xCC) >> 2) | ((b & 0x33) << 2));
  b = (u8) (((b & 0xAA) >> 1) | ((b & 0x55) << 1));
  return b;
}

DECLSPEC u32 iclass_mac (PRIVATE_AS const u8 *rev_ccnr, PRIVATE_AS const u8 *div_key)
{
  iclass_state_t state;
  state.l = (u8) (((div_key[0] ^ 0x4C) + 0xEC) & 0xFF);
  state.r = (u8) (((div_key[0] ^ 0x4C) + 0x21) & 0xFF);
  state.b = 0x4C;
  state.t = 0xE012;

  for (int i = 0; i < 12; i++)
  {
    const u8 rb = rev_ccnr[i];
    for (int bit = 7; bit >= 0; bit--)
    {
      state = iclass_successor (div_key, state, (rb >> bit) & 1);
    }
  }

  u8 mac[4] = { 0, 0, 0, 0 };

  for (int i = 0; i < 4; i++)
  {
    for (int bit = 7; bit >= 0; bit--)
    {
      mac[i] |= (u8) (((state.r >> 2) & 1) << bit);
      state = iclass_successor (div_key, state, 0);
    }
  }

  return ((u32) reflect8 (mac[0]) << 24)
       | ((u32) reflect8 (mac[1]) << 16)
       | ((u32) reflect8 (mac[2]) <<  8)
       | ((u32) reflect8 (mac[3])      );
}

DECLSPEC void unpack_be32 (const u32 w, PRIVATE_AS u8 *out)
{
  out[0] = (u8) (w >> 24);
  out[1] = (u8) (w >> 16);
  out[2] = (u8) (w >>  8);
  out[3] = (u8) (w      );
}

typedef struct pcfg_hash_ctx
{
  u32 mac2_target;

  u8 pk[8];

  u8 rev_ccnr1[12];
  u8 rev_ccnr2[12];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->mac2_target = salt_bufs[salt_pos].salt_buf[8];

  unpack_be32 (salt_bufs[salt_pos].salt_buf[0], hc->pk + 0);
  unpack_be32 (salt_bufs[salt_pos].salt_buf[1], hc->pk + 4);

  u8 ccnr1_bytes[12];

  unpack_be32 (salt_bufs[salt_pos].salt_buf[2], ccnr1_bytes + 0);
  unpack_be32 (salt_bufs[salt_pos].salt_buf[3], ccnr1_bytes + 4);
  unpack_be32 (salt_bufs[salt_pos].salt_buf[4], ccnr1_bytes + 8);

  for (int i = 0; i < 12; i++) hc->rev_ccnr1[i] = reflect8 (ccnr1_bytes[i]);

  u8 ccnr2_bytes[12];

  unpack_be32 (salt_bufs[salt_pos].salt_buf[5], ccnr2_bytes + 0);
  unpack_be32 (salt_bufs[salt_pos].salt_buf[6], ccnr2_bytes + 4);
  unpack_be32 (salt_bufs[salt_pos].salt_buf[7], ccnr2_bytes + 8);

  for (int i = 0; i < 12; i++) hc->rev_ccnr2[i] = reflect8 (ccnr2_bytes[i]);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

// The second MAC is checked here rather than by the framework, because it lives in the salt and not
// in the digest. A candidate that fails it is reported as no match at all.

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 len, PRIVATE_AS u32 *dgst)
{
  const u64 idx = ((u64) (w[1] & 0xFF) << 32) | (u64) w[0];

  u8 div_key[8];

  for (int j = 0; j < 8; j++)
  {
    div_key[j] = (hc->pk[j] & 0x07) | (u8) (((idx >> (35 - 5 * j)) & 0x1F) << 3);
  }

  u8 rev_ccnr2[12];

  for (int i = 0; i < 12; i++) rev_ccnr2[i] = hc->rev_ccnr2[i];

  const u32 computed2 = iclass_mac (rev_ccnr2, div_key);

  if (computed2 != hc->mac2_target) return false;

  u8 rev_ccnr1[12];

  for (int i = 0; i < 12; i++) rev_ccnr1[i] = hc->rev_ccnr1[i];

  const u32 computed1 = iclass_mac (rev_ccnr1, div_key);

  dgst[0] = computed1;
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[2];

  t[0] = w[0];
  t[1] = w[1];

  const bool ok = pcfg_hash (hc, t, len, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m36901_mxx
#define PCFG_KERNEL_SXX m36901_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
