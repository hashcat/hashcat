/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void sha256_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void sha256_init (sha256_ctx_t *ctx);
DECLSPEC void sha256_update_64 (sha256_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha256_update (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_swap (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le_swap (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_global (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_swap (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le_swap (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_final (sha256_ctx_t *ctx);
DECLSPEC void sha256_hmac_init_64 (sha256_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void sha256_hmac_init (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global (sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global_swap (sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_64 (sha256_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha256_hmac_update (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_swap (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le_swap (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_final (sha256_hmac_ctx_t *ctx);
DECLSPEC void sha256_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void sha256_init_vector (sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_init_vector_from_scalar (sha256_ctx_vector_t *ctx, sha256_ctx_t *ctx0);
DECLSPEC void sha256_update_vector_64 (sha256_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha256_update_vector (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_swap (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le_swap (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16beN (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_final_vector (sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_hmac_init_vector_64 (sha256_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void sha256_hmac_init_vector (sha256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_hmac_update_vector_64 (sha256_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha256_hmac_update_vector (sha256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_hmac_final_vector (sha256_hmac_ctx_vector_t *ctx);
