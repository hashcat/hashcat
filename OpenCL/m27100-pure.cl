/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// #define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

typedef struct netntlmv2_tmp
{
  u32 digest_buf[4];

} netntlm_tmp_t;


KERNEL_FQ void m27100_init (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  tmps[gid].digest_buf[0] = out[ 0];
  tmps[gid].digest_buf[1] = out[ 1];
  tmps[gid].digest_buf[2] = out[ 2];
  tmps[gid].digest_buf[3] = out[ 3];

}


KERNEL_FQ void m27100_loop (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
{


}

KERNEL_FQ void m27100_comp (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
{
   /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = tmps[gid].digest_buf[0];
  w0[1] = tmps[gid].digest_buf[1];
  w0[2] = tmps[gid].digest_buf[2];
  w0[3] = tmps[gid].digest_buf[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_hmac_ctx_t ctx0;

  md5_hmac_init_64 (&ctx0, w0, w1, w2, w3);

  md5_hmac_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].userdomain_buf, esalt_bufs[DIGESTS_OFFSET_HOST].user_len + esalt_bufs[DIGESTS_OFFSET_HOST].domain_len);

  md5_hmac_final (&ctx0);

  w0[0] = ctx0.opad.h[0];
  w0[1] = ctx0.opad.h[1];
  w0[2] = ctx0.opad.h[2];
  w0[3] = ctx0.opad.h[3];
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  md5_hmac_ctx_t ctx;

  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  md5_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].chall_buf, esalt_bufs[DIGESTS_OFFSET_HOST].srvchall_len + esalt_bufs[DIGESTS_OFFSET_HOST].clichall_len);

  md5_hmac_final (&ctx);

  tmps[gid].digest_buf[0] = ctx.opad.h[0];
  tmps[gid].digest_buf[1] = ctx.opad.h[1];
  tmps[gid].digest_buf[2] = ctx.opad.h[2];
  tmps[gid].digest_buf[3] = ctx.opad.h[3];


  /**
   * digest
   */

  const u32 r0 = ctx.opad.h[DGST_R0];
  const u32 r1 = ctx.opad.h[DGST_R1];
  const u32 r2 = ctx.opad.h[DGST_R2];
  const u32 r3 = ctx.opad.h[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
