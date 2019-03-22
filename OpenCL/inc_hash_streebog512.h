/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void streebog512_init (streebog512_ctx_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_add (u64 *x, const u64 *y);
DECLSPEC void streebog512_g (u64 *h, const u64 *n, const u64 *m, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_transform (streebog512_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void streebog512_update_64 (streebog512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void streebog512_update (streebog512_ctx_t *ctx, const u32 *w, int len);
DECLSPEC void streebog512_update_swap (streebog512_ctx_t *ctx, const u32 *w, int len);
DECLSPEC void streebog512_update_global_swap (streebog512_ctx_t *ctx, const GLOBAL_AS u32 *w, int len);
DECLSPEC void streebog512_final (streebog512_ctx_t *ctx);
DECLSPEC void streebog512_hmac_init_64 (streebog512_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_init (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_init_swap (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_update_64 (streebog512_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void streebog512_hmac_update (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void streebog512_hmac_update_swap (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void streebog512_hmac_update_global_swap (streebog512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void streebog512_hmac_final (streebog512_hmac_ctx_t *ctx);
DECLSPEC void streebog512_init_vector (streebog512_ctx_vector_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_add_vector (u64x *x, const u64x *y);
DECLSPEC void streebog512_g_vector (u64x *h, const u64x *n, const u64x *m, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_transform_vector (streebog512_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void streebog512_update_vector_64 (streebog512_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void streebog512_update_vector (streebog512_ctx_vector_t *ctx, const u32x *w, int len);
DECLSPEC void streebog512_update_vector_swap (streebog512_ctx_vector_t *ctx, const u32x *w, int len);
DECLSPEC void streebog512_final_vector (streebog512_ctx_vector_t *ctx);
DECLSPEC void streebog512_hmac_init_vector_64 (streebog512_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_init_vector (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_init_vector_swap (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256]);
DECLSPEC void streebog512_hmac_update_vector (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void streebog512_hmac_update_vector_swap (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void streebog512_hmac_final_vector (streebog512_hmac_ctx_vector_t *ctx);
