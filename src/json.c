/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "json.h"

#include <stdarg.h>
#include <string.h>

// Routes output to the FILE, or appends it to the fixed buffer, bounded so a short buffer truncates
// rather than overruns. The buffer stays NUL terminated.
static void json_write (json_ctx_t *ctx, const char *text, const size_t len)
{
  if (ctx->fp != NULL)
  {
    fwrite (text, 1, len, ctx->fp);

    return;
  }

  if (ctx->buf_len + len < ctx->buf_size)
  {
    memcpy (ctx->buf + ctx->buf_len, text, len);

    ctx->buf_len += len;
    ctx->buf[ctx->buf_len] = 0;
  }
}

static void json_puts (json_ctx_t *ctx, const char *text)
{
  json_write (ctx, text, strlen (text));
}

static void json_putc (json_ctx_t *ctx, const char c)
{
  json_write (ctx, &c, 1);
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

void json_init_buffer (json_ctx_t *ctx, char *buf, const size_t size)
{
  memset (ctx, 0, sizeof (json_ctx_t));

  ctx->buf      = buf;
  ctx->buf_size = size;

  if (size > 0) buf[0] = 0;
}

void json_object_begin (json_ctx_t *ctx)
{
  json_pre_value (ctx);

  json_putc (ctx, '{');

  if (ctx->depth >= JSON_MAX_DEPTH) return;

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

  if (ctx->depth >= JSON_MAX_DEPTH) return;

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

void json_kv_bool (json_ctx_t *ctx, const char *key, const bool value)
{
  json_key (ctx, key);
  json_bool (ctx, value);
}

void json_kv_hex (json_ctx_t *ctx, const char *key, const unsigned char *data, const size_t len)
{
  static const char hex[] = "0123456789abcdef";

  json_key (ctx, key);

  json_pre_value (ctx);

  json_putc (ctx, '"');

  for (size_t i = 0; i < len; i++)
  {
    json_putc (ctx, hex[data[i] >> 4]);
    json_putc (ctx, hex[data[i] & 0x0f]);
  }

  json_putc (ctx, '"');
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
