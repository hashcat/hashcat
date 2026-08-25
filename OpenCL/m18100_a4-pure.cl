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

DECLSPEC void _totp_calculate (PRIVATE_AS u32 *code, PRIVATE_AS const u32 *w, const u32 pw_len, PRIVATE_AS const u32 *s, const u32 salt_len)
{
  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_swap (&ctx, w, pw_len);

  sha1_hmac_update (&ctx, s, salt_len);

  sha1_hmac_final (&ctx);

  // initialize a buffer for the otp code
  u32 otp_code = 0;

  // grab 4 consecutive bytes of the hash, starting at offset
  switch (ctx.opad.h[4] & 15)
  {
    case  0: otp_code = ctx.opad.h[0];                              break;
    case  1: otp_code = ctx.opad.h[0] <<  8 | ctx.opad.h[1] >> 24;  break;
    case  2: otp_code = ctx.opad.h[0] << 16 | ctx.opad.h[1] >> 16;  break;
    case  3: otp_code = ctx.opad.h[0] << 24 | ctx.opad.h[1] >>  8;  break;
    case  4: otp_code = ctx.opad.h[1];                              break;
    case  5: otp_code = ctx.opad.h[1] <<  8 | ctx.opad.h[2] >> 24;  break;
    case  6: otp_code = ctx.opad.h[1] << 16 | ctx.opad.h[2] >> 16;  break;
    case  7: otp_code = ctx.opad.h[1] << 24 | ctx.opad.h[2] >>  8;  break;
    case  8: otp_code = ctx.opad.h[2];                              break;
    case  9: otp_code = ctx.opad.h[2] <<  8 | ctx.opad.h[3] >> 24;  break;
    case 10: otp_code = ctx.opad.h[2] << 16 | ctx.opad.h[3] >> 16;  break;
    case 11: otp_code = ctx.opad.h[2] << 24 | ctx.opad.h[3] >>  8;  break;
    case 12: otp_code = ctx.opad.h[3];                              break;
    case 13: otp_code = ctx.opad.h[3] <<  8 | ctx.opad.h[4] >> 24;  break;
    case 14: otp_code = ctx.opad.h[3] << 16 | ctx.opad.h[4] >> 16;  break;
    case 15: otp_code = ctx.opad.h[3] << 24 | ctx.opad.h[4] >>  8;  break;
  }

  // take only the lower 31 bits
  otp_code &= 0x7fffffff;

  // we want to generate only 6 digits of code
  *code = otp_code % 1000000;
}

typedef struct pcfg_hash_ctx
{
  u32 count;
  u32 s[64];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->count = salt_bufs[salt_pos].salt_len / 16;

  for (u32 i = 0; i < 64; i++) hc->s[i] = 0;

  for (u32 i = 0; i < hc->count; i += 1)
  {
    hc->s[16 * i + 0] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[4 * i + 0]);
    hc->s[16 * i + 1] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[4 * i + 1]);
  }
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 otp_code0 = 0;
  u32 otp_code1 = 0;
  u32 otp_code2 = 0;
  u32 otp_code3 = 0;

  if (hc->count == 1)
  {
    _totp_calculate (&otp_code0, w, len, hc->s, 8);
  }
  else if (hc->count == 2)
  {
    _totp_calculate (&otp_code0, w, len, hc->s +  0, 8);
    _totp_calculate (&otp_code1, w, len, hc->s + 16, 8);
  }
  else if (hc->count == 3)
  {
    _totp_calculate (&otp_code0, w, len, hc->s +  0, 8);
    _totp_calculate (&otp_code1, w, len, hc->s + 16, 8);
    _totp_calculate (&otp_code2, w, len, hc->s + 32, 8);
  }
  else if (hc->count == 4)
  {
    _totp_calculate (&otp_code0, w, len, hc->s +  0, 8);
    _totp_calculate (&otp_code1, w, len, hc->s + 16, 8);
    _totp_calculate (&otp_code2, w, len, hc->s + 32, 8);
    _totp_calculate (&otp_code3, w, len, hc->s + 48, 8);
  }

  dgst[0] = otp_code0;
  dgst[1] = otp_code1;
  dgst[2] = otp_code2;
  dgst[3] = otp_code3;

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m18100_mxx
#define PCFG_KERNEL_SXX m18100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
