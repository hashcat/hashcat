/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_mysql323.h"

// Input is little endian words, as for MD5: the bytes are taken in memory order.

DECLSPEC void mysql323_init (PRIVATE_AS mysql323_ctx_t *ctx)
{
  ctx->nr  = 0x50305735;
  ctx->nr2 = 0x12345671;
  ctx->add = 7;

  ctx->len = 0;
}

DECLSPEC void mysql323_byte (PRIVATE_AS mysql323_ctx_t *ctx, const u32 c)
{
  if (c == 0x20) return;
  if (c == 0x09) return;

  ctx->nr  ^= (((ctx->nr & 63) + ctx->add) * c) + (ctx->nr << 8);
  ctx->nr2 += (ctx->nr2 << 8) ^ ctx->nr;
  ctx->add += c;
}

DECLSPEC void mysql323_update (PRIVATE_AS mysql323_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

// Widen ASCII to UTF-16LE: each byte, then a zero byte, which is not skipped.

DECLSPEC void mysql323_update_utf16le (PRIVATE_AS mysql323_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      mysql323_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mysql323_byte (ctx, 0);
  }
}

DECLSPEC void mysql323_update_global (PRIVATE_AS mysql323_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

DECLSPEC void mysql323_update_global_utf16le (PRIVATE_AS mysql323_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      mysql323_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mysql323_byte (ctx, 0);
  }
}

// A context with invalid UTF-8 input produces the digest with the 31 bits of each word flipped, so
// that no candidate matches it by chance.

DECLSPEC void mysql323_final (PRIVATE_AS mysql323_ctx_t *ctx)
{
  ctx->nr  &= 0x7fffffff;
  ctx->nr2 &= 0x7fffffff;

  if (ctx->len < 0)
  {
    ctx->nr  ^= 0x7fffffff;
    ctx->nr2 ^= 0x7fffffff;
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. A byte that is a
// space or a tab in one lane only has its effect masked off in that lane. Its UTF-16LE update
// widens ASCII only, as the vector updates of the other families do.

DECLSPEC void mysql323_init_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx)
{
  ctx->nr  = 0x50305735;
  ctx->nr2 = 0x12345671;
  ctx->add = 7;

  ctx->len = 0;
}

DECLSPEC void mysql323_byte_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx, const u32x c)
{
  // 1 where c is neither a space nor a tab: (t | -t) has its top bit set exactly when t is not 0

  const u32x ts = c ^ 0x20;
  const u32x tt = c ^ 0x09;

  const u32x keep = ((ts | (~ts + 1)) >> 31) & ((tt | (~tt + 1)) >> 31);

  const u32x mask = ~keep + 1;

  ctx->nr  ^= ((((ctx->nr & 63) + ctx->add) * c) + (ctx->nr << 8)) & mask;
  ctx->nr2 += ((ctx->nr2 << 8) ^ ctx->nr) & mask;
  ctx->add += c & mask;
}

DECLSPEC void mysql323_update_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
  }
}

DECLSPEC void mysql323_update_vector_utf16le (PRIVATE_AS mysql323_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i++)
  {
    mysql323_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
    mysql323_byte_vector (ctx, make_u32x (0));
  }
}

DECLSPEC void mysql323_final_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx)
{
  ctx->nr  &= 0x7fffffff;
  ctx->nr2 &= 0x7fffffff;
}
