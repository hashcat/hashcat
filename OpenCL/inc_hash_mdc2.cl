/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_des.h"
#include "inc_hash_mdc2.h"

DECLSPEC void mdc2_init (PRIVATE_AS mdc2_ctx_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64])
{
  ctx->h[0]  = 0x52525252;
  ctx->h[1]  = 0x52525252;
  ctx->hh[0] = 0x25252525;
  ctx->hh[1] = 0x25252525;

  ctx->w[0] = 0;
  ctx->w[1] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->s_skb     = s_skb;
  ctx->s_sptrans = s_sptrans;
}

// Each half of the state keys a DES encryption of the block, after setting bits 6 and 5 of its
// first byte to 10 for h and to 01 for hh. Both results are xored with the block, and the new
// halves swap their second words.

DECLSPEC void mdc2_block (PRIVATE_AS mdc2_ctx_t *ctx)
{
  u32 Kc[16];
  u32 Kd[16];

  u32 o1[2];
  u32 o2[2];

  _des_crypt_keysetup ((ctx->h[0] & 0xffffff9f) | 0x40, ctx->h[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt (o1, ctx->w, Kc, Kd, ctx->s_sptrans);

  _des_crypt_keysetup ((ctx->hh[0] & 0xffffff9f) | 0x20, ctx->hh[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt (o2, ctx->w, Kc, Kd, ctx->s_sptrans);

  ctx->h[0]  = o1[0] ^ ctx->w[0];
  ctx->h[1]  = o2[1] ^ ctx->w[1];
  ctx->hh[0] = o2[0] ^ ctx->w[0];
  ctx->hh[1] = o1[1] ^ ctx->w[1];

  ctx->w[0] = 0;
  ctx->w[1] = 0;

  ctx->pos = 0;
}

DECLSPEC void mdc2_byte (PRIVATE_AS mdc2_ctx_t *ctx, const u32 c)
{
  const int pos = ctx->pos;

  ctx->w[pos / 4] |= c << ((pos & 3) * 8);

  ctx->pos = pos + 1;

  if (ctx->pos == 8) mdc2_block (ctx);
}

DECLSPEC void mdc2_update (PRIVATE_AS mdc2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len < 0) return;

  ctx->len += len;

  for (int i = 0; i < len; i++) mdc2_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

// Widen ASCII to UTF-16LE: each byte, then a zero byte.

DECLSPEC void mdc2_update_utf16le (PRIVATE_AS mdc2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      mdc2_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len < 0) return;

  ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mdc2_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mdc2_byte (ctx, 0);
  }
}

DECLSPEC void mdc2_update_global (PRIVATE_AS mdc2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len < 0) return;

  ctx->len += len;

  for (int i = 0; i < len; i++) mdc2_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void mdc2_update_global_utf16le (PRIVATE_AS mdc2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      mdc2_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len < 0) return;

  ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mdc2_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mdc2_byte (ctx, 0);
  }
}

// A partial last block is hashed with zero bytes after it. An empty message and one that ends on a
// block boundary get no further block, as in OpenSSL. A context with invalid UTF-8 input produces
// the digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void mdc2_final (PRIVATE_AS mdc2_ctx_t *ctx)
{
  if (ctx->pos > 0) mdc2_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 2; i++) ctx->h[i]  = ~ctx->h[i];
    for (u32 i = 0; i < 2; i++) ctx->hh[i] = ~ctx->hh[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void mdc2_init_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64])
{
  ctx->h[0]  = 0x52525252;
  ctx->h[1]  = 0x52525252;
  ctx->hh[0] = 0x25252525;
  ctx->hh[1] = 0x25252525;

  ctx->w[0] = 0;
  ctx->w[1] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->s_skb     = s_skb;
  ctx->s_sptrans = s_sptrans;
}

DECLSPEC void mdc2_block_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx)
{
  u32x Kc[16];
  u32x Kd[16];

  u32x o1[2];
  u32x o2[2];

  _des_crypt_keysetup_vect ((ctx->h[0] & 0xffffff9f) | 0x40, ctx->h[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt_vect (o1, ctx->w, Kc, Kd, ctx->s_sptrans);

  _des_crypt_keysetup_vect ((ctx->hh[0] & 0xffffff9f) | 0x20, ctx->hh[1], Kc, Kd, ctx->s_skb);

  _des_crypt_encrypt_vect (o2, ctx->w, Kc, Kd, ctx->s_sptrans);

  ctx->h[0]  = o1[0] ^ ctx->w[0];
  ctx->h[1]  = o2[1] ^ ctx->w[1];
  ctx->hh[0] = o2[0] ^ ctx->w[0];
  ctx->hh[1] = o1[1] ^ ctx->w[1];

  ctx->w[0] = 0;
  ctx->w[1] = 0;

  ctx->pos = 0;
}

DECLSPEC void mdc2_byte_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, const u32x c)
{
  const int pos = ctx->pos;

  ctx->w[pos / 4] |= c << ((pos & 3) * 8);

  ctx->pos = pos + 1;

  if (ctx->pos == 8) mdc2_block_vector (ctx);
}

DECLSPEC void mdc2_update_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len < 0) return;

  ctx->len += len;

  for (int i = 0; i < len; i++) mdc2_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void mdc2_update_vector_utf16le (PRIVATE_AS mdc2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len < 0) return;

  ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mdc2_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mdc2_byte_vector (ctx, make_u32x (0));
  }
}

DECLSPEC void mdc2_final_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx)
{
  if (ctx->pos > 0) mdc2_block_vector (ctx);
}
