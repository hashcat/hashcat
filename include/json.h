/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_JSON_H
#define HC_JSON_H

#include <stdbool.h>
#include <stdio.h>

// A small RFC 8259 JSON emitter. It tracks the open objects and arrays and inserts the commas and
// the "key": separators, and it escapes every string, so no caller builds JSON by hand or forgets
// to escape a path. It writes to a FILE (stdout, or an outfile) in the spaced style hashcat has
// always printed, or into a caller-provided fixed buffer with no allocation, for the outfile line
// that is built once per cracked hash and must stay off the heap.

#define JSON_MAX_DEPTH 32

typedef struct json_ctx
{
  FILE  *fp;             // write target when non-NULL

  char  *buf;            // fixed caller buffer target when fp is NULL
  size_t buf_len;        // bytes written so far (the finished length the caller reads back)
  size_t buf_size;       // capacity of buf, including room for the NUL

  bool   overflow;       // a buffer write did not fit; all further output is dropped from there on

  int    depth;          // number of open containers
  bool   need_sep[JSON_MAX_DEPTH + 1]; // whether the next item at this depth needs a leading comma
  bool   after_key;      // the last thing written was a key, so the next value takes no comma
} json_ctx_t;

// Write to a FILE.
void json_init (json_ctx_t *ctx, FILE *fp);

// Write into a caller-owned fixed buffer with no allocation; the caller reads ctx->buf_len back as
// the finished length. Output past size - 1 is dropped, so size the buffer for the worst case.
void json_init_buffer (json_ctx_t *ctx, char *buf, size_t size);

void json_object_begin (json_ctx_t *ctx);
void json_object_end   (json_ctx_t *ctx);
void json_array_begin  (json_ctx_t *ctx);
void json_array_end    (json_ctx_t *ctx);

// A key inside an object. The next json_* call supplies its value.
void json_key (json_ctx_t *ctx, const char *key);

// Values. json_string escapes text per RFC 8259; a NULL text is written as a JSON null.
void json_string (json_ctx_t *ctx, const char *text);
void json_int    (json_ctx_t *ctx, long long value);
void json_uint   (json_ctx_t *ctx, unsigned long long value);
void json_bool   (json_ctx_t *ctx, bool value);
void json_null   (json_ctx_t *ctx);

// Emits a value exactly as given, for a number a caller has already formatted, for example to a
// fixed number of decimals. The text must be a valid JSON token; the emitter does not check it.
void json_raw (json_ctx_t *ctx, const char *token);

// A key whose value is the hex encoding of a byte buffer, as "<key>": "<hex>". The bytes need no
// escaping, so this writes them straight out; it is how the outfile JSON carries its fields.
void json_kv_hex (json_ctx_t *ctx, const char *key, const unsigned char *data, size_t len);

// Key plus value in one call, for the common "key": value pair.
void json_kv_string (json_ctx_t *ctx, const char *key, const char *text);
void json_kv_int    (json_ctx_t *ctx, const char *key, long long value);
void json_kv_uint   (json_ctx_t *ctx, const char *key, unsigned long long value);
void json_kv_bool   (json_ctx_t *ctx, const char *key, bool value);

// A key whose value is a printf-formatted string, for the outputs that spell even their numbers as
// strings ("Processors": "16"). The formatted text is escaped like any other string.
void json_kv_fmt (json_ctx_t *ctx, const char *key, const char *fmt, ...);

#endif // HC_JSON_H
