/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void md5_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void md5_init (md5_ctx_t *ctx);
DECLSPEC void md5_update_64 (md5_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md5_update (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_swap (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_utf16le (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_utf16le_swap (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_global (md5_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_update_global_swap (md5_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_update_global_utf16le (md5_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_update_global_utf16le_swap (md5_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_final (md5_ctx_t *ctx);
DECLSPEC void md5_hmac_init_64 (md5_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void md5_hmac_init (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_init_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_init_global (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_init_global_swap (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_update_64 (md5_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md5_hmac_update (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_utf16le (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_utf16le_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_global (md5_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_swap (md5_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_utf16le (md5_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_utf16le_swap (md5_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void md5_hmac_final (md5_hmac_ctx_t *ctx);
DECLSPEC void md5_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void md5_init_vector (md5_ctx_vector_t *ctx);
DECLSPEC void md5_init_vector_from_scalar (md5_ctx_vector_t *ctx, md5_ctx_t *ctx0);
DECLSPEC void md5_update_vector_64 (md5_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md5_update_vector (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_swap (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_utf16le (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_utf16le_swap (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_final_vector (md5_ctx_vector_t *ctx);
DECLSPEC void md5_hmac_init_vector_64 (md5_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void md5_hmac_init_vector (md5_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_hmac_update_vector_64 (md5_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md5_hmac_update_vector (md5_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_hmac_final_vector (md5_hmac_ctx_vector_t *ctx);
