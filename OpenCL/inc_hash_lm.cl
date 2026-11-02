/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_des.h"
#include "inc_hash_lm.h"

// The string KGS!@#$% as little endian words.

#define LM_MAGIC_0 0x2153474b
#define LM_MAGIC_1 0x25242340

// Spread the 7 bytes in w0 and w1 over the 8 bytes of a DES key, 7 bits each. The lowest bit of a
// key byte is its parity bit, which DES ignores.

DECLSPEC void lm_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *key)
{
  const u32 t0 = (w0 >>  0) & 0xff;
  const u32 t1 = (w0 >>  8) & 0xff;
  const u32 t2 = (w0 >> 16) & 0xff;
  const u32 t3 = (w0 >> 24) & 0xff;
  const u32 t4 = (w1 >>  0) & 0xff;
  const u32 t5 = (w1 >>  8) & 0xff;
  const u32 t6 = (w1 >> 16) & 0xff;

  const u32 k0 =             (t0 >> 0);
  const u32 k1 = (t0 << 7) | (t1 >> 1);
  const u32 k2 = (t1 << 6) | (t2 >> 2);
  const u32 k3 = (t2 << 5) | (t3 >> 3);
  const u32 k4 = (t3 << 4) | (t4 >> 4);
  const u32 k5 = (t4 << 3) | (t5 >> 5);
  const u32 k6 = (t5 << 2) | (t6 >> 6);
  const u32 k7 = (t6 << 1);

  key[0] = ((k0 & 0xff) <<  0)
         | ((k1 & 0xff) <<  8)
         | ((k2 & 0xff) << 16)
         | ((k3 & 0xff) << 24);

  key[1] = ((k4 & 0xff) <<  0)
         | ((k5 & 0xff) <<  8)
         | ((k6 & 0xff) << 16)
         | ((k7 & 0xff) << 24);
}

DECLSPEC void lm_init (PRIVATE_AS lm_ctx_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64])
{
  for (u32 i = 0; i < 4; i++) ctx->w[i] = 0;
  for (u32 i = 0; i < 4; i++) ctx->h[i] = 0;

  ctx->len = 0;

  ctx->s_skb     = s_skb;
  ctx->s_sptrans = s_sptrans;
}

// Keep a byte while fewer than 14 are kept. Later bytes do not change the hash.

DECLSPEC void lm_byte (PRIVATE_AS lm_ctx_t *ctx, const u32 c)
{
  const int pos = ctx->len;

  if (pos < 0)   return;
  if (pos >= 14) return;

  ctx->w[pos / 4] |= c << ((pos & 3) * 8);

  ctx->len = pos + 1;
}

DECLSPEC void lm_update (PRIVATE_AS lm_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

// Widen ASCII to UTF-16LE: each byte, then a zero byte.

DECLSPEC void lm_update_utf16le (PRIVATE_AS lm_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      lm_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    lm_byte (ctx, 0);
  }
}

DECLSPEC void lm_update_global (PRIVATE_AS lm_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

DECLSPEC void lm_update_global_utf16le (PRIVATE_AS lm_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      lm_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    lm_byte (ctx, 0);
  }
}

// Convert lowercase ASCII letters to uppercase, 4 bytes at a time: a byte is a lowercase letter
// exactly when its bit 7 is clear, adding 0x1f to its low 7 bits sets bit 7, and adding 0x05 does
// not. Bytes 7 to 13 start at the top byte of word 1. A context with invalid UTF-8 input produces
// the digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void lm_final (PRIVATE_AS lm_ctx_t *ctx)
{
  u32 w[4];

  for (u32 i = 0; i < 4; i++)
  {
    const u32 v = ctx->w[i];
    const u32 a = v & 0x7f7f7f7f;

    w[i] = v ^ ((~(a + 0x05050505) & (a + 0x1f1f1f1f) & ~v & 0x80808080) >> 2);
  }

  u32 data[2];

  data[0] = LM_MAGIC_0;
  data[1] = LM_MAGIC_1;

  u32 key[2];

  u32 Kc[16];
  u32 Kd[16];

  u32 out[2];

  lm_key (w[0], w[1], key);

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt (out, data, Kc, Kd, ctx->s_sptrans);

  ctx->h[0] = out[0];
  ctx->h[1] = out[1];

  lm_key ((w[1] >> 24) | (w[2] << 8), (w[2] >> 24) | (w[3] << 8), key);

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt (out, data, Kc, Kd, ctx->s_sptrans);

  ctx->h[2] = out[0];
  ctx->h[3] = out[1];

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void lm_key_vector (const u32x w0, const u32x w1, PRIVATE_AS u32x *key)
{
  const u32x t0 = (w0 >>  0) & 0xff;
  const u32x t1 = (w0 >>  8) & 0xff;
  const u32x t2 = (w0 >> 16) & 0xff;
  const u32x t3 = (w0 >> 24) & 0xff;
  const u32x t4 = (w1 >>  0) & 0xff;
  const u32x t5 = (w1 >>  8) & 0xff;
  const u32x t6 = (w1 >> 16) & 0xff;

  const u32x k0 =             (t0 >> 0);
  const u32x k1 = (t0 << 7) | (t1 >> 1);
  const u32x k2 = (t1 << 6) | (t2 >> 2);
  const u32x k3 = (t2 << 5) | (t3 >> 3);
  const u32x k4 = (t3 << 4) | (t4 >> 4);
  const u32x k5 = (t4 << 3) | (t5 >> 5);
  const u32x k6 = (t5 << 2) | (t6 >> 6);
  const u32x k7 = (t6 << 1);

  key[0] = ((k0 & 0xff) <<  0)
         | ((k1 & 0xff) <<  8)
         | ((k2 & 0xff) << 16)
         | ((k3 & 0xff) << 24);

  key[1] = ((k4 & 0xff) <<  0)
         | ((k5 & 0xff) <<  8)
         | ((k6 & 0xff) << 16)
         | ((k7 & 0xff) << 24);
}

DECLSPEC void lm_init_vector (PRIVATE_AS lm_ctx_vector_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64])
{
  for (u32 i = 0; i < 4; i++) ctx->w[i] = 0;
  for (u32 i = 0; i < 4; i++) ctx->h[i] = 0;

  ctx->len = 0;

  ctx->s_skb     = s_skb;
  ctx->s_sptrans = s_sptrans;
}

DECLSPEC void lm_byte_vector (PRIVATE_AS lm_ctx_vector_t *ctx, const u32x c)
{
  const int pos = ctx->len;

  if (pos < 0)   return;
  if (pos >= 14) return;

  ctx->w[pos / 4] |= c << ((pos & 3) * 8);

  ctx->len = pos + 1;
}

DECLSPEC void lm_update_vector (PRIVATE_AS lm_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

DECLSPEC void lm_update_vector_utf16le (PRIVATE_AS lm_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  for (int i = 0; i < len; i++)
  {
    if (ctx->len < 0)   break;
    if (ctx->len >= 14) break;

    lm_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    lm_byte_vector (ctx, make_u32x (0));
  }
}

DECLSPEC void lm_final_vector (PRIVATE_AS lm_ctx_vector_t *ctx)
{
  u32x w[4];

  for (u32 i = 0; i < 4; i++)
  {
    const u32x v = ctx->w[i];
    const u32x a = v & 0x7f7f7f7f;

    w[i] = v ^ ((~(a + 0x05050505) & (a + 0x1f1f1f1f) & ~v & 0x80808080) >> 2);
  }

  u32x data[2];

  data[0] = LM_MAGIC_0;
  data[1] = LM_MAGIC_1;

  u32x key[2];

  u32x Kc[16];
  u32x Kd[16];

  u32x out[2];

  lm_key_vector (w[0], w[1], key);

  _des_crypt_keysetup_vect (key[0], key[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt_vect (out, data, Kc, Kd, ctx->s_sptrans);

  ctx->h[0] = out[0];
  ctx->h[1] = out[1];

  lm_key_vector ((w[1] >> 24) | (w[2] << 8), (w[2] >> 24) | (w[3] << 8), key);

  _des_crypt_keysetup_vect (key[0], key[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt_vect (out, data, Kc, Kd, ctx->s_sptrans);

  ctx->h[2] = out[0];
  ctx->h[3] = out[1];
}
