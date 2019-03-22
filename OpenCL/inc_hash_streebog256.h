/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void streebog256_init (streebog256_ctx_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_add (u64 *x, const u64 *y);
DECLSPEC void streebog256_g (u64 *h, const u64 *n, const u64 *m, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_transform (streebog256_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void streebog256_update_64 (streebog256_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void streebog256_update (streebog256_ctx_t *ctx, const u32 *w, int len);
DECLSPEC void streebog256_update_swap (streebog256_ctx_t *ctx, const u32 *w, int len);
DECLSPEC void streebog256_update_global_swap (streebog256_ctx_t *ctx, const GLOBAL_AS u32 *w, int len);
DECLSPEC void streebog256_final (streebog256_ctx_t *ctx);
DECLSPEC void streebog256_hmac_init_64 (streebog256_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_init (streebog256_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_init_swap (streebog256_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_update_64 (streebog256_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void streebog256_hmac_update (streebog256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void streebog256_hmac_update_swap (streebog256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void streebog256_hmac_update_global_swap (streebog256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void streebog256_hmac_final (streebog256_hmac_ctx_t *ctx);
DECLSPEC void streebog256_init_vector (streebog256_ctx_vector_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_add_vector (u64x *x, const u64x *y);
DECLSPEC void streebog256_g_vector (u64x *h, const u64x *n, const u64x *m, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_transform_vector (streebog256_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void streebog256_update_vector_64 (streebog256_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void streebog256_update_vector (streebog256_ctx_vector_t *ctx, const u32x *w, int len);
DECLSPEC void streebog256_update_vector_swap (streebog256_ctx_vector_t *ctx, const u32x *w, int len);
DECLSPEC void streebog256_final_vector (streebog256_ctx_vector_t *ctx);
DECLSPEC void streebog256_hmac_init_vector_64 (streebog256_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_init_vector (streebog256_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_init_vector_swap (streebog256_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog256_hmac_update_vector (streebog256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void streebog256_hmac_update_vector_swap (streebog256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void streebog256_hmac_final_vector (streebog256_hmac_ctx_vector_t *ctx);
