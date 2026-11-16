/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_AUTH_POLY1305_H
#define INC_AUTH_POLY1305_H

// Poly1305 using 26-bit limbs (stored in 32-bit values)
// Based on poly1305-donna for correctness

typedef struct poly1305_ctx
{
  u32 r[5];       // 26-bit limbs for r
  u32 h[5];       // 26-bit limbs for accumulator
  u32 pad[4];     // 32-bit padding values
  u32 buffer[4];
  u32 buffer_left;
} poly1305_ctx_t;

DECLSPEC void poly1305_init           (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *key);
DECLSPEC void poly1305_blocks         (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *m, const u32 blocks);
DECLSPEC void poly1305_update_global  (PRIVATE_AS poly1305_ctx_t *ctx, GLOBAL_AS const u32 *m, const u32 bytes);
DECLSPEC void poly1305_update_private (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS const u32 *m, const u32 bytes);
DECLSPEC void poly1305_update_pad     (PRIVATE_AS poly1305_ctx_t *ctx, const u32 bytes);
DECLSPEC void poly1305_final          (PRIVATE_AS poly1305_ctx_t *ctx, PRIVATE_AS u32 *mac);

#endif // INC_AUTH_POLY1305_H
