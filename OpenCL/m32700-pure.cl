/**
 * Author......: hansvh
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct sha1_tmp
{
  u32 salt32[8];
  u32 newdes_key32[60];

} sha1_tmp_t;

CONSTANT_VK u32 newdes_rotor[256] =
{
  0x20, 0x89, 0xef, 0xbc, 0x66, 0x7d, 0xdd, 0x48, 0xd4, 0x44, 0x51, 0x25, 0x56, 0xed, 0x93, 0x95,
  0x46, 0xe5, 0x11, 0x7c, 0x73, 0xcf, 0x21, 0x14, 0x7a, 0x8f, 0x19, 0xd7, 0x33, 0xb7, 0x8a, 0x8e,
  0x92, 0xd3, 0x6e, 0xad, 0x01, 0xe4, 0xbd, 0x0e, 0x67, 0x4e, 0xa2, 0x24, 0xfd, 0xa7, 0x74, 0xff,
  0x9e, 0x2d, 0xb9, 0x32, 0x62, 0xa8, 0xfa, 0xeb, 0x36, 0x8d, 0xc3, 0xf7, 0xf0, 0x3f, 0x94, 0x02,
  0xe0, 0xa9, 0xd6, 0xb4, 0x3e, 0x16, 0x75, 0x6c, 0x13, 0xac, 0xa1, 0x9f, 0xa0, 0x2f, 0x2b, 0xab,
  0xc2, 0xaf, 0xb2, 0x38, 0xc4, 0x70, 0x17, 0xdc, 0x59, 0x15, 0xa4, 0x82, 0x9d, 0x08, 0x55, 0xfb,
  0xd8, 0x2c, 0x5e, 0xb3, 0xe2, 0x26, 0x5a, 0x77, 0x28, 0xca, 0x22, 0xce, 0x23, 0x45, 0xe7, 0xf6,
  0x1d, 0x6d, 0x4a, 0x47, 0xb0, 0x06, 0x3c, 0x91, 0x41, 0x0d, 0x4d, 0x97, 0x0c, 0x7f, 0x5f, 0xc7,
  0x39, 0x65, 0x05, 0xe8, 0x96, 0xd2, 0x81, 0x18, 0xb5, 0x0a, 0x79, 0xbb, 0x30, 0xc1, 0x8b, 0xfc,
  0xdb, 0x40, 0x58, 0xe9, 0x60, 0x80, 0x50, 0x35, 0xbf, 0x90, 0xda, 0x0b, 0x6a, 0x84, 0x9b, 0x68,
  0x5b, 0x88, 0x1f, 0x2a, 0xf3, 0x42, 0x7e, 0x87, 0x1e, 0x1a, 0x57, 0xba, 0xb6, 0x9a, 0xf2, 0x7b,
  0x52, 0xa6, 0xd0, 0x27, 0x98, 0xbe, 0x71, 0xcd, 0x72, 0x69, 0xe1, 0x54, 0x49, 0xa3, 0x63, 0x6f,
  0xcc, 0x3d, 0xc8, 0xd9, 0xaa, 0x0f, 0xc6, 0x1c, 0xc0, 0xfe, 0x86, 0xea, 0xde, 0x07, 0xec, 0xf8,
  0xc9, 0x29, 0xb1, 0x9c, 0x5c, 0x83, 0x43, 0xf9, 0xf5, 0xb8, 0xcb, 0x09, 0xf1, 0x00, 0x1b, 0x2e,
  0x85, 0xae, 0x4b, 0x12, 0x5d, 0xd1, 0x64, 0x78, 0x4c, 0xd5, 0x10, 0x53, 0x04, 0x6b, 0x8c, 0x34,
  0x3a, 0x37, 0x03, 0xf4, 0x61, 0xc5, 0xee, 0xe3, 0x76, 0x31, 0x4f, 0xe6, 0xdf, 0xa5, 0x99, 0x3b,
};

DECLSPEC void new_des (u32 *block, u32 *newdes_key)
{
  #define B0 (*(block+0))
  #define B1 (*(block+1))
  #define B2 (*(block+2))
  #define B3 (*(block+3))
  #define B4 (*(block+4))
  #define B5 (*(block+5))
  #define B6 (*(block+6))
  #define B7 (*(block+7))

  for (int count = 0; count < 8; count++)
  {
    B4 = B4 ^ newdes_rotor[B0 ^ *(newdes_key++)];
    B5 = B5 ^ newdes_rotor[B1 ^ *(newdes_key++)];
    B6 = B6 ^ newdes_rotor[B2 ^ *(newdes_key++)];
    B7 = B7 ^ newdes_rotor[B3 ^ *(newdes_key++)];

    B1 = B1 ^ newdes_rotor[B4 ^ *(newdes_key++)];
    B2 = B2 ^ newdes_rotor[B4 ^ B5];
    B3 = B3 ^ newdes_rotor[B6 ^ *(newdes_key++)];
    B0 = B0 ^ newdes_rotor[B7 ^ *(newdes_key++)];
  }

  B4 = B4 ^ newdes_rotor[B0 ^ *(newdes_key++)];
  B5 = B5 ^ newdes_rotor[B1 ^ *(newdes_key++)];
  B6 = B6 ^ newdes_rotor[B2 ^ *(newdes_key++)];
  B7 = B7 ^ newdes_rotor[B3 ^ *(newdes_key++)];
}

DECLSPEC void key_expansion (const u8 *sha1sum, u32 *result)
{
  for (int count = 0; count < 15; count++)
  {
    const u8 shi = sha1sum[count];

    result[0] = shi;
    result[1] = shi ^ sha1sum[7]; // ??? will be always zero for byte 24, 29, 34
    result[2] = shi ^ sha1sum[8];
    result[3] = shi ^ sha1sum[9];

    result += 4;
  }
}

DECLSPEC void sha1_final_32700 (PRIVATE_AS sha1_ctx_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos);

  if (pos >= 56)
  {
    sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = 0;
  ctx->w3[3] = hc_swap32_S (ctx->len * 8);

  sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

KERNEL_FQ void m32700_init (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Initial "SHA-1" (with endianness bug)
  sha1_ctx_t ctx;

  sha1_init (&ctx);
  sha1_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
  sha1_final_32700 (&ctx);
  // sha1_final (&ctx);

  ctx.h[0] = hc_swap32_S (ctx.h[0]);
  ctx.h[1] = hc_swap32_S (ctx.h[1]);
  ctx.h[2] = hc_swap32_S (ctx.h[2]);
  ctx.h[3] = hc_swap32_S (ctx.h[3]);
  ctx.h[4] = hc_swap32_S (ctx.h[4]);

  // Crate a NewDES key
  u32 newdes_key32[60];

  key_expansion ((const u8 *) ctx.h, newdes_key32);

  for (int i = 0; i < 60; i++)
  {
    tmps[gid].newdes_key32[i] = newdes_key32[i];
  }

  for (int i = 0, j = 0; i < 8; i += 4, j += 1)
  {
    const u32 salt = salt_bufs[SALT_POS_HOST].salt_buf[j];

    tmps[gid].salt32[i + 0] = unpack_v8a_from_v32_S (salt);
    tmps[gid].salt32[i + 1] = unpack_v8b_from_v32_S (salt);
    tmps[gid].salt32[i + 2] = unpack_v8c_from_v32_S (salt);
    tmps[gid].salt32[i + 3] = unpack_v8d_from_v32_S (salt);
  }
}

KERNEL_FQ void m32700_loop (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 newdes_key32[60];

  for (int i = 0; i < 60; i++)
  {
    newdes_key32[i] = tmps[gid].newdes_key32[i];
  }

  u32 salt32[8];

  for (int i = 0; i < 8; i++)
  {
    salt32[i] = tmps[gid].salt32[i];
  }

  // Run 1000 iterations of NewDES on the derived salt
  for (int i = 0; i < LOOP_CNT; i++)
  {
    new_des (salt32, newdes_key32);
  }

  for (int i = 0; i < 8; i++)
  {
    tmps[gid].salt32[i] = salt32[i];
  }
}

KERNEL_FQ void m32700_comp (KERN_ATTR_TMPS (sha1_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 salt[16] = { 0 };

  salt[0] = (tmps[gid].salt32[0] <<  0)
          | (tmps[gid].salt32[1] <<  8)
          | (tmps[gid].salt32[2] << 16)
          | (tmps[gid].salt32[3] << 24);

  salt[1] = (tmps[gid].salt32[4] <<  0)
          | (tmps[gid].salt32[5] <<  8)
          | (tmps[gid].salt32[6] << 16)
          | (tmps[gid].salt32[7] << 24);

  // Final "SHA-1" (with endianness bug)
  sha1_ctx_t ctx;

  sha1_init (&ctx);
  sha1_update (&ctx, salt, 8);
  sha1_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
  sha1_final_32700 (&ctx);

  const u32 r0 = ctx.h[0];
  const u32 r1 = ctx.h[1];
  const u32 r2 = ctx.h[2];
  const u32 r3 = ctx.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
