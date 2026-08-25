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
#endif

typedef struct pcfg_hash_ctx
{
  u32 salt_len;
  u32 s[64];

  u32 salt_len_pc;
  u32 s_pc[64];

  u32 salt_iter;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len; i += 4, idx += 1)
  {
    hc->s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  hc->salt_len_pc = salt_bufs[salt_pos].salt_len_pc;

  for (u32 i = 0; i < 64; i++) hc->s_pc[i] = 0;

  for (u32 i = 0, idx = 0; i < hc->salt_len_pc; i += 4, idx += 1)
  {
    hc->s_pc[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf_pc[idx]);
  }

  hc->salt_iter = salt_bufs[salt_pos].salt_iter;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  // replace "." with the length:

  if (len > 0)
  {
    u32 t[64] = { 0 };

    for (u32 i = 0, idx = 0; i < len; i += 4, idx += 1) t[idx] = w[idx];

    u32 label_len = 0;

    for (int pos = len - 1; pos >= 0; pos--)
    {
      const u32 div = pos  / 4;
      const u32 mod = pos  & 3;
      const u32 sht = mod << 3;

      if (((t[div] >> sht) & 0xff) == 0x2e) // '.'
      {
        t[div] += (label_len - 0x2e) << sht;

        label_len = 0;

        continue;
      }

      label_len++;
    }

    ctx1.w0[0] = (label_len & 0xff) << 24;

    ctx1.len = 1;

    sha1_update_swap (&ctx1, t, len);
  }

  sha1_update (&ctx1, hc->s_pc, hc->salt_len_pc + 1);

  sha1_update (&ctx1, hc->s, hc->salt_len);

  sha1_final (&ctx1);

  u32 digest[5];

  digest[0] = ctx1.h[0];
  digest[1] = ctx1.h[1];
  digest[2] = ctx1.h[2];
  digest[3] = ctx1.h[3];
  digest[4] = ctx1.h[4];

  // iterations

  for (u32 i = 0; i < hc->salt_iter; i++)
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);

    ctx.w0[0] = digest[0];
    ctx.w0[1] = digest[1];
    ctx.w0[2] = digest[2];
    ctx.w0[3] = digest[3];
    ctx.w1[0] = digest[4];

    ctx.len = 20;

    sha1_update (&ctx, hc->s, hc->salt_len);

    sha1_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
  }

  dgst[0] = digest[DGST_R0];
  dgst[1] = digest[DGST_R1];
  dgst[2] = digest[DGST_R2];
  dgst[3] = digest[DGST_R3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64];

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool ok = pcfg_hash (hc, t, len, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m08300_mxx
#define PCFG_KERNEL_SXX m08300_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
