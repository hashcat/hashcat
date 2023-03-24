/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}
#endif

typedef struct dcc_tmp
{
  u32 digest_buf[4];

} dcc_tmp_t;


KERNEL_FQ void m31500_init (KERN_ATTR_TMPS (dcc_tmp_t))
{
 /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];

  u32 out[4];

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

  for (int i = 0, j = 0; i < 16; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].digest_buf[0] = out[0];
  tmps[gid].digest_buf[1] = out[1];
  tmps[gid].digest_buf[2] = out[2];
  tmps[gid].digest_buf[3] = out[3];
}

KERNEL_FQ void m31500_loop (KERN_ATTR_TMPS (dcc_tmp_t))
{

}

KERNEL_FQ void m31500_comp (KERN_ATTR_TMPS (dcc_tmp_t))
{
 /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

 /**
   * salt
   */

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  const u32 a = tmps[gid].digest_buf[0];
  const u32 b = tmps[gid].digest_buf[1];
  const u32 c = tmps[gid].digest_buf[2];
  const u32 d = tmps[gid].digest_buf[3];

  md4_ctx_t ctx;

  md4_init (&ctx);

  ctx.w0[0] = a;
  ctx.w0[1] = b;
  ctx.w0[2] = c;
  ctx.w0[3] = d;

  ctx.len = 16;

  md4_update_utf16le (&ctx, s, salt_len);

  md4_final (&ctx);

  const u32 r0  = ctx.h[DGST_R0];
  const u32 r1  = ctx.h[DGST_R1];
  const u32 r2  = ctx.h[DGST_R2];
  const u32 r3  = ctx.h[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}