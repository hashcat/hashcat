/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

DECLSPEC void whirlpool_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init (whirlpool_ctx_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_update_64 (whirlpool_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void whirlpool_update (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_global (whirlpool_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_update_global_swap (whirlpool_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le (whirlpool_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le_swap (whirlpool_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_final (whirlpool_ctx_t *ctx);
DECLSPEC void whirlpool_hmac_init_64 (whirlpool_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_update_64 (whirlpool_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void whirlpool_hmac_update (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global (whirlpool_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_swap (whirlpool_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le (whirlpool_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le_swap (whirlpool_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void whirlpool_hmac_final (whirlpool_hmac_ctx_t *ctx);
DECLSPEC void whirlpool_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init_vector (whirlpool_ctx_vector_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init_vector_from_scalar (whirlpool_ctx_vector_t *ctx, whirlpool_ctx_t *ctx0);
DECLSPEC void whirlpool_update_vector_64 (whirlpool_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_update_vector (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_final_vector (whirlpool_ctx_vector_t *ctx);
DECLSPEC void whirlpool_hmac_init_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_update_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_hmac_update_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_hmac_final_vector (whirlpool_hmac_ctx_vector_t *ctx);
