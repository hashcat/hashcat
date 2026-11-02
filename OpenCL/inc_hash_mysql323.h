/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_MYSQL323_H
#define INC_HASH_MYSQL323_H

// The password hash used by MySQL before 4.1, OLD_PASSWORD (). It processes one byte at a time and
// skips spaces and tabs, as MySQL does. The digest contains nr and nr2 with their top bits removed,
// printed as 2 big endian words.

typedef struct mysql323_ctx
{
  u32 nr;
  u32 nr2;
  u32 add;

  // Number of bytes hashed, or -1 if the input contains invalid UTF-8.

  int len;

} mysql323_ctx_t;

typedef struct mysql323_ctx_vector
{
  u32x nr;
  u32x nr2;
  u32x add;

  int len;

} mysql323_ctx_vector_t;

DECLSPEC void mysql323_init (PRIVATE_AS mysql323_ctx_t *ctx);
DECLSPEC void mysql323_byte (PRIVATE_AS mysql323_ctx_t *ctx, const u32 c);
DECLSPEC void mysql323_update (PRIVATE_AS mysql323_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void mysql323_update_utf16le (PRIVATE_AS mysql323_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void mysql323_update_global (PRIVATE_AS mysql323_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void mysql323_update_global_utf16le (PRIVATE_AS mysql323_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void mysql323_final (PRIVATE_AS mysql323_ctx_t *ctx);

DECLSPEC void mysql323_init_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx);
DECLSPEC void mysql323_byte_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx, const u32x c);
DECLSPEC void mysql323_update_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void mysql323_update_vector_utf16le (PRIVATE_AS mysql323_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void mysql323_final_vector (PRIVATE_AS mysql323_ctx_vector_t *ctx);

#endif // INC_HASH_MYSQL323_H
