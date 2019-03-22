/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void sha224_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void sha224_init (sha224_ctx_t *ctx);
DECLSPEC void sha224_update_64 (sha224_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha224_update (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_swap (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_utf16le (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_utf16le_swap (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_global (sha224_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_update_global_swap (sha224_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_update_global_utf16le (sha224_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_update_global_utf16le_swap (sha224_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_final (sha224_ctx_t *ctx);
DECLSPEC void sha224_hmac_init_64 (sha224_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void sha224_hmac_init (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_global (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_global_swap (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_64 (sha224_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha224_hmac_update (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_utf16le (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_utf16le_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global (sha224_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_swap (sha224_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_utf16le (sha224_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_utf16le_swap (sha224_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha224_hmac_final (sha224_hmac_ctx_t *ctx);
DECLSPEC void sha224_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void sha224_init_vector (sha224_ctx_vector_t *ctx);
DECLSPEC void sha224_init_vector_from_scalar (sha224_ctx_vector_t *ctx, sha224_ctx_t *ctx0);
DECLSPEC void sha224_update_vector_64 (sha224_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha224_update_vector (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_swap (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16le (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16le_swap (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16beN (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_final_vector (sha224_ctx_vector_t *ctx);
DECLSPEC void sha224_hmac_init_vector_64 (sha224_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void sha224_hmac_init_vector (sha224_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_hmac_update_vector_64 (sha224_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha224_hmac_update_vector (sha224_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_hmac_final_vector (sha224_hmac_ctx_vector_t *ctx);
