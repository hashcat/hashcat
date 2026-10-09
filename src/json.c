/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "json.h"

#include <math.h>
#include <stdarg.h>
#include <string.h>

// Grows the accumulation buffer so at least extra more bytes and a NUL fit. A FILE target keeps no
// buffer, so this is a no-op there. A failed allocation sets overflow, and every later write then
// does nothing, so json_finish can report it once rather than each call having to.
static void json_reserve (json_ctx_t *ctx, const size_t extra)
{
  if (ctx->fp != NULL) return;
  if (ctx->overflow == true) return;

  const size_t need = ctx->buf_len + extra + 1;

  if (need <= ctx->buf_size) return;

  size_t size = (ctx->buf_size == 0) ? 256 : ctx->buf_size;

  while (size < need) size *= 2;

  char *tmp = (char *) realloc (ctx->buf, size);

  if (tmp == NULL)
  {
    ctx->overflow = true;

    return;
  }

  ctx->buf      = tmp;
  ctx->buf_size = size;
}

static void json_write (json_ctx_t *ctx, const char *text, const size_t len)
{
  if (ctx->fp != NULL)
  {
    fwrite (text, 1, len, ctx->fp);

    return;
  }

  json_reserve (ctx, len);

  if (ctx->overflow == true) return;

  memcpy (ctx->buf + ctx->buf_len, text, len);

  ctx->buf_len += len;
  ctx->buf[ctx->buf_len] = 0;
}

static void json_putc (json_ctx_t *ctx, const char c)
{
  json_write (ctx, &c, 1);
}

static void json_puts (json_ctx_t *ctx, const char *text)
{
  json_write (ctx, text, strlen (text));
}

// Writes a string value or key with the quotes and the RFC 8259 escaping: the named short escapes,
// \u00XX for the other control characters below 0x20, and the backslash and the double quote. Bytes
// at 0x80 and above pass through as the UTF-8 the strings already are.
static void json_write_escaped (json_ctx_t *ctx, const char *text)
{
  json_putc (ctx, '"');

  for (const unsigned char *p = (const unsigned char *) text; *p != 0; p++)
  {
    const unsigned char c = *p;

    switch (c)
    {
      case '"':  json_puts (ctx, "\\\""); continue;
      case '\\': json_puts (ctx, "\\\\"); continue;
      case '\b': json_puts (ctx, "\\b");  continue;
      case '\t': json_puts (ctx, "\\t");  continue;
      case '\n': json_puts (ctx, "\\n");  continue;
      case '\f': json_puts (ctx, "\\f");  continue;
      case '\r': json_puts (ctx, "\\r");  continue;
    }

    if (c < 0x20)
    {
      char esc[7];

      snprintf (esc, sizeof (esc), "\\u%04x", c);

      json_puts (ctx, esc);

      continue;
    }

    json_putc (ctx, (char) c);
  }

  json_putc (ctx, '"');
}

// Writes the separator before an item (an object key or an array element) in the spaced style
// hashcat has always printed: a single space after the opening brace or bracket for the first item,
// ", " before each one after it, and the level is marked non-empty so the close knows to add its
// own space. A top level value has no surrounding container, so it takes neither.
static void json_item_sep (json_ctx_t *ctx)
{
  if (ctx->depth > 0)
  {
    json_puts (ctx, (ctx->need_sep[ctx->depth] == true) ? ", " : " ");
  }

  ctx->need_sep[ctx->depth] = true;
}

// Runs before any value (including a nested object or array). The value of a key already had its
// separator written with the key, so it only clears the flag; an array element writes its own.
static void json_pre_value (json_ctx_t *ctx)
{
  if (ctx->after_key == true)
  {
    ctx->after_key = false;

    return;
  }

  json_item_sep (ctx);
}

void json_init (json_ctx_t *ctx, FILE *fp)
{
  memset (ctx, 0, sizeof (json_ctx_t));

  ctx->fp = fp;
}

const char *json_finish (json_ctx_t *ctx)
{
  if (ctx->fp != NULL) return NULL;
  if (ctx->overflow == true) return NULL;

  return (ctx->buf != NULL) ? ctx->buf : "";
}

void json_free (json_ctx_t *ctx)
{
  if (ctx->buf != NULL)
  {
    free (ctx->buf);

    ctx->buf      = NULL;
    ctx->buf_len  = 0;
    ctx->buf_size = 0;
  }
}

void json_object_begin (json_ctx_t *ctx)
{
  json_pre_value (ctx);

  json_putc (ctx, '{');

  if (ctx->depth >= JSON_MAX_DEPTH)
  {
    ctx->overflow = true;

    return;
  }

  ctx->depth++;
  ctx->need_sep[ctx->depth] = false;
}

void json_object_end (json_ctx_t *ctx)
{
  // A space before the brace when the object held something, so it reads "{ ... }"; an empty object
  // stays "{}".
  json_puts (ctx, (ctx->need_sep[ctx->depth] == true) ? " }" : "}");

  if (ctx->depth > 0) ctx->depth--;
}

void json_array_begin (json_ctx_t *ctx)
{
  json_pre_value (ctx);

  json_putc (ctx, '[');

  if (ctx->depth >= JSON_MAX_DEPTH)
  {
    ctx->overflow = true;

    return;
  }

  ctx->depth++;
  ctx->need_sep[ctx->depth] = false;
}

void json_array_end (json_ctx_t *ctx)
{
  json_puts (ctx, (ctx->need_sep[ctx->depth] == true) ? " ]" : "]");

  if (ctx->depth > 0) ctx->depth--;
}

void json_key (json_ctx_t *ctx, const char *key)
{
  json_item_sep (ctx);

  json_write_escaped (ctx, key);

  json_puts (ctx, ": ");

  ctx->after_key = true;
}

void json_string (json_ctx_t *ctx, const char *text)
{
  if (text == NULL)
  {
    json_null (ctx);

    return;
  }

  json_pre_value (ctx);

  json_write_escaped (ctx, text);
}

void json_int (json_ctx_t *ctx, const long long value)
{
  json_pre_value (ctx);

  char tmp[32];

  snprintf (tmp, sizeof (tmp), "%lld", value);

  json_puts (ctx, tmp);
}

void json_uint (json_ctx_t *ctx, const unsigned long long value)
{
  json_pre_value (ctx);

  char tmp[32];

  snprintf (tmp, sizeof (tmp), "%llu", value);

  json_puts (ctx, tmp);
}

void json_double (json_ctx_t *ctx, const double value)
{
  json_pre_value (ctx);

  // JSON has no way to spell a NaN or an infinity, so a non finite value becomes null rather than
  // an unparsable token.
  if (isfinite (value) == 0)
  {
    json_puts (ctx, "null");

    return;
  }

  char tmp[64];

  snprintf (tmp, sizeof (tmp), "%f", value);

  json_puts (ctx, tmp);
}

void json_bool (json_ctx_t *ctx, const bool value)
{
  json_pre_value (ctx);

  json_puts (ctx, (value == true) ? "true" : "false");
}

void json_null (json_ctx_t *ctx)
{
  json_pre_value (ctx);

  json_puts (ctx, "null");
}

void json_raw (json_ctx_t *ctx, const char *token)
{
  json_pre_value (ctx);

  json_puts (ctx, token);
}

void json_kv_fmt (json_ctx_t *ctx, const char *key, const char *fmt, ...)
{
  char buf[512];

  va_list ap;

  va_start (ap, fmt);

  vsnprintf (buf, sizeof (buf), fmt, ap);

  va_end (ap);

  json_kv_string (ctx, key, buf);
}

void json_kv_string (json_ctx_t *ctx, const char *key, const char *text)
{
  json_key (ctx, key);
  json_string (ctx, text);
}

void json_kv_int (json_ctx_t *ctx, const char *key, const long long value)
{
  json_key (ctx, key);
  json_int (ctx, value);
}

void json_kv_uint (json_ctx_t *ctx, const char *key, const unsigned long long value)
{
  json_key (ctx, key);
  json_uint (ctx, value);
}

void json_kv_double (json_ctx_t *ctx, const char *key, const double value)
{
  json_key (ctx, key);
  json_double (ctx, value);
}

void json_kv_bool (json_ctx_t *ctx, const char *key, const bool value)
{
  json_key (ctx, key);
  json_bool (ctx, value);
}
