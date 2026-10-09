/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_JSON_H
#define HC_JSON_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// A small RFC 8259 JSON emitter. It tracks the open objects and arrays and inserts the commas and
// the "key": separators, and it escapes every string, so no caller builds JSON by hand or forgets
// to escape a path. It writes to a FILE (stdout or an outfile) when one is given, or accumulates
// into a buffer the caller reads back when fp is NULL, so the same code serves the streamed outputs
// and the ones that have to hand a finished string to the event log.

#define JSON_MAX_DEPTH 32

typedef struct json_ctx
{
  FILE  *fp;             // write target, or NULL to accumulate into buf

  char  *buf;            // accumulation buffer, valid while fp is NULL
  size_t buf_len;
  size_t buf_size;

  int    depth;          // number of open containers
  bool   need_sep[JSON_MAX_DEPTH + 1]; // whether the next item at this depth needs a leading comma
  bool   after_key;      // the last thing written was a key, so the next value takes no comma

  bool   overflow;       // a buffer allocation failed, or the depth went out of range
} json_ctx_t;

// fp NULL accumulates into an internal buffer, read back with json_finish.
void json_init (json_ctx_t *ctx, FILE *fp);

// Flushes nothing for a FILE target. For a buffer target it returns the NUL terminated JSON, which
// stays owned by ctx until json_free. Returns NULL when an allocation failed along the way.
const char *json_finish (json_ctx_t *ctx);

// Frees the accumulation buffer. Safe to call for a FILE target.
void json_free (json_ctx_t *ctx);

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
void json_double (json_ctx_t *ctx, double value);
void json_bool   (json_ctx_t *ctx, bool value);
void json_null   (json_ctx_t *ctx);

// Emits a value exactly as given, for a number a caller has already formatted, for example to a
// fixed number of decimals. The text must be a valid JSON token; the emitter does not check it.
void json_raw (json_ctx_t *ctx, const char *token);

// A key whose value is a printf-formatted string, for the outputs that spell even their numbers as
// strings ("Processors": "16"). The formatted text is escaped like any other string.
void json_kv_fmt (json_ctx_t *ctx, const char *key, const char *fmt, ...);

// Key plus value in one call, for the common "key": value pair.
void json_kv_string (json_ctx_t *ctx, const char *key, const char *text);
void json_kv_int    (json_ctx_t *ctx, const char *key, long long value);
void json_kv_uint   (json_ctx_t *ctx, const char *key, unsigned long long value);
void json_kv_double (json_ctx_t *ctx, const char *key, double value);
void json_kv_bool   (json_ctx_t *ctx, const char *key, bool value);

#endif // HC_JSON_H
