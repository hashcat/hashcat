/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Mikrotik RouterOS EC-SRP5 (Curve25519)
 *
 * Algorithm:
 *   inner  = SHA256(username + ":" + password)
 *   scalar = SHA256(salt_16bytes + inner)
 *   point  = scalar * G  on Curve25519 (Weierstrass form)
 *   x_mont = (point.x + conversion_to_m) % p
 *   verifier = first 28 bytes of x_mont (big-endian)
 *
 * Kernel architecture (ATTACK_EXEC_OUTSIDE_KERNEL):
 *   init: compute scalar from password+username+salt, store in tmps
 *   loop: no-op (single-pass algorithm)
 *   comp: EC scalar multiply, convert to Montgomery, compare
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_ecc_curve25519.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct mikrotik_ecsrp5_tmp
{
  u32 out[8];

} mikrotik_ecsrp5_tmp_t;

KERNEL_FQ KERNEL_FA void m33200_init (KERN_ATTR_TMPS (mikrotik_ecsrp5_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * Step 1: inner = SHA256(username + ":" + password)
   *
   * Build "username:password" in a local buffer (LE u32), feed with sha256_update_swap.
   */

  const u32 username_len = salt_bufs[SALT_POS_HOST].salt_len_pc;
  const u32 pw_len = pws[gid].pw_len;
  const u32 total_len = username_len + 1 + pw_len;

  u32 w_tmp[64];

  // Explicit zero init
  for (u32 i = 0; i < 64; i++) w_tmp[i] = 0;

  // Copy username bytes from salt_buf_pc (LE u32 / native byte order)
  for (u32 i = 0; i < (username_len + 3) / 4; i++)
  {
    w_tmp[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[i];
  }

  // Append ":" at byte position username_len
  {
    const u32 wi = username_len / 4;
    const u32 bi = username_len % 4;
    w_tmp[wi] |= ((u32) 0x3a) << (bi * 8);
  }

  // Append password bytes
  for (u32 i = 0; i < pw_len; i++)
  {
    const u32 src_word = i / 4;
    const u32 src_byte = i % 4;
    const u32 dst_pos = username_len + 1 + i;
    const u32 dst_word = dst_pos / 4;
    const u32 dst_byte = dst_pos % 4;

    const u32 b = (pws[gid].i[src_word] >> (src_byte * 8)) & 0xff;
    w_tmp[dst_word] |= (b << (dst_byte * 8));
  }

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_swap (&ctx, w_tmp, total_len);

  sha256_final (&ctx);

  // ctx.h[0..7] = inner hash (BE u32)

  /**
   * Step 2: scalar = SHA256(salt_16bytes + inner_32bytes)
   *
   * Build salt(16B)+inner(32B) = 48 bytes, all in BE u32, single update.
   */

  u32 msg2[16];

  // Salt: LE u32 from hex_to_u32 -> swap to BE
  msg2[ 0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  msg2[ 1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);
  msg2[ 2] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[2]);
  msg2[ 3] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[3]);

  // Inner hash: already BE u32 from ctx.h[]
  msg2[ 4] = ctx.h[0];
  msg2[ 5] = ctx.h[1];
  msg2[ 6] = ctx.h[2];
  msg2[ 7] = ctx.h[3];
  msg2[ 8] = ctx.h[4];
  msg2[ 9] = ctx.h[5];
  msg2[10] = ctx.h[6];
  msg2[11] = ctx.h[7];

  // Pad remaining words to zero (sha256_update reads 16 words)
  msg2[12] = 0;
  msg2[13] = 0;
  msg2[14] = 0;
  msg2[15] = 0;

  sha256_ctx_t ctx2;

  sha256_init (&ctx2);

  sha256_update (&ctx2, msg2, 48);

  sha256_final (&ctx2);

  // ctx2.h[0..7] = scalar hash (BE u32)

  /**
   * Store scalar in tmps as LE u32 for ECC code
   * BE u32 h[0] is MSW, needs to go to k[7] (LE position for MSW)
   */

  tmps[gid].out[0] = ctx2.h[7];
  tmps[gid].out[1] = ctx2.h[6];
  tmps[gid].out[2] = ctx2.h[5];
  tmps[gid].out[3] = ctx2.h[4];
  tmps[gid].out[4] = ctx2.h[3];
  tmps[gid].out[5] = ctx2.h[2];
  tmps[gid].out[6] = ctx2.h[1];
  tmps[gid].out[7] = ctx2.h[0];
}

KERNEL_FQ KERNEL_FA void m33200_loop (KERN_ATTR_TMPS (mikrotik_ecsrp5_tmp_t))
{
  // No-op: single-pass algorithm, ECC computed in comp
}

KERNEL_FQ KERNEL_FA void m33200_comp (KERN_ATTR_TMPS (mikrotik_ecsrp5_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  /**
   * Step 3: point = scalar * G on Curve25519 (Weierstrass form)
   */

  u32 scalar[8];

  scalar[0] = tmps[gid].out[0];
  scalar[1] = tmps[gid].out[1];
  scalar[2] = tmps[gid].out[2];
  scalar[3] = tmps[gid].out[3];
  scalar[4] = tmps[gid].out[4];
  scalar[5] = tmps[gid].out[5];
  scalar[6] = tmps[gid].out[6];
  scalar[7] = tmps[gid].out[7];

  curve25519_t coords;

  curve25519_set_precomputed_basepoint_g (&coords);

  u32 x1[8], y1[8];

  curve25519_point_mul_xy (x1, y1, scalar, &coords);

  /**
   * Step 4: x_mont = (x_weierstrass + conversion_to_m) mod p
   */

  u32 conv[8];

  conv[0] = CURVE25519_CONV_TO_M0;
  conv[1] = CURVE25519_CONV_TO_M1;
  conv[2] = CURVE25519_CONV_TO_M2;
  conv[3] = CURVE25519_CONV_TO_M3;
  conv[4] = CURVE25519_CONV_TO_M4;
  conv[5] = CURVE25519_CONV_TO_M5;
  conv[6] = CURVE25519_CONV_TO_M6;
  conv[7] = CURVE25519_CONV_TO_M7;

  u32 x_mont[8];

  curve25519_add_mod (x_mont, x1, conv);

  /**
   * Step 5: Compare
   *
   * x_mont is LE u32: x_mont[7] = MSW = first 4 bytes of big-endian representation.
   * digest stores BE u32 from byte_swap_32(hex_to_u32(...)), which is the numeric value
   * of the first 4 bytes. Both are the same numeric value, no swap needed.
   */

  const u32 r0 = x_mont[7];   // digest[0]
  const u32 r1 = x_mont[6];   // digest[1]
  const u32 r2 = x_mont[5];   // digest[2]
  const u32 r3 = x_mont[4];   // digest[3]

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
