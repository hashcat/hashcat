/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void md4_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void md4_init (md4_ctx_t *ctx);
DECLSPEC void md4_update_64 (md4_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md4_update (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_swap (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_utf16le (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_utf16le_swap (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_global (md4_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_update_global_swap (md4_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_update_global_utf16le (md4_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_update_global_utf16le_swap (md4_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_final (md4_ctx_t *ctx);
DECLSPEC void md4_hmac_init_64 (md4_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void md4_hmac_init (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_init_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_init_global (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_init_global_swap (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_update_64 (md4_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md4_hmac_update (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_utf16le (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_utf16le_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_global (md4_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_swap (md4_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_utf16le (md4_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_utf16le_swap (md4_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md4_hmac_final (md4_hmac_ctx_t *ctx);
DECLSPEC void md4_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void md4_init_vector (md4_ctx_vector_t *ctx);
DECLSPEC void md4_init_vector_from_scalar (md4_ctx_vector_t *ctx, md4_ctx_t *ctx0);
DECLSPEC void md4_update_vector_64 (md4_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md4_update_vector (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_swap (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_utf16le (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_utf16le_swap (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_final_vector (md4_ctx_vector_t *ctx);
DECLSPEC void md4_hmac_init_vector_64 (md4_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void md4_hmac_init_vector (md4_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_hmac_update_vector_64 (md4_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md4_hmac_update_vector (md4_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_hmac_final_vector (md4_hmac_ctx_vector_t *ctx);
