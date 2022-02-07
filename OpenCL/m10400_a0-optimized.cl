/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m04 (KERN_ATTR_RULES_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * constant
   */

  const u32 padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[0];
  o_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[1];
  o_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[2];
  o_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[3];
  o_buf[4] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[4];
  o_buf[5] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[5];
  o_buf[6] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[6];
  o_buf[7] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[7];

  u32 P = esalt_bufs[DIGESTS_OFFSET_HOST].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[0];
  id_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[1];
  id_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[2];
  id_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pdf
     */

    u32 p0[4];
    u32 p1[4];
    u32 p2[4];
    u32 p3[4];

    p0[0] = padding[0];
    p0[1] = padding[1];
    p0[2] = padding[2];
    p0[3] = padding[3];
    p1[0] = padding[4];
    p1[1] = padding[5];
    p1[2] = padding[6];
    p1[3] = padding[7];
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    switch_buffer_by_offset_le (p0, p1, p2, p3, out_len);

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0[0] |= p0[0];
    w0[1] |= p0[1];
    w0[2] |= p0[2];
    w0[3] |= p0[3];
    w1[0] |= p1[0];
    w1[1] |= p1[1];
    w1[2] |= p1[2];
    w1[3] |= p1[3];
    w2[0]  = o_buf[0];
    w2[1]  = o_buf[1];
    w2[2]  = o_buf[2];
    w2[3]  = o_buf[3];
    w3[0]  = o_buf[4];
    w3[1]  = o_buf[5];
    w3[2]  = o_buf[6];
    w3[3]  = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    w0[0] = P;
    w0[1] = id_buf[0];
    w0[2] = id_buf[1];
    w0[3] = id_buf[2];
    w1[0] = id_buf[3];
    w1[1] = 0x80;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 84 * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, digest);

    // now the RC4 part

    digest[1] = digest[1] & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    rc4_init_40 (S, digest, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, padding, out, lid);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m08 (KERN_ATTR_RULES_ESALT (pdf_t))
{
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_m16 (KERN_ATTR_RULES_ESALT (pdf_t))
{
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_s04 (KERN_ATTR_RULES_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * constant
   */

  const u32 padding[8] =
  {
    0x5e4ebf28,
    0x418a754e,
    0x564e0064,
    0x0801faff,
    0xb6002e2e,
    0x803e68d0,
    0xfea90c2f,
    0x7a695364
  };

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[0];
  o_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[1];
  o_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[2];
  o_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[3];
  o_buf[4] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[4];
  o_buf[5] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[5];
  o_buf[6] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[6];
  o_buf[7] = esalt_bufs[DIGESTS_OFFSET_HOST].o_buf[7];

  u32 P = esalt_bufs[DIGESTS_OFFSET_HOST].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[0];
  id_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[1];
  id_buf[2] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[2];
  id_buf[3] = esalt_bufs[DIGESTS_OFFSET_HOST].id_buf[3];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pdf
     */

    u32 p0[4];
    u32 p1[4];
    u32 p2[4];
    u32 p3[4];

    p0[0] = padding[0];
    p0[1] = padding[1];
    p0[2] = padding[2];
    p0[3] = padding[3];
    p1[0] = padding[4];
    p1[1] = padding[5];
    p1[2] = padding[6];
    p1[3] = padding[7];
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    switch_buffer_by_offset_le (p0, p1, p2, p3, out_len);

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0[0] |= p0[0];
    w0[1] |= p0[1];
    w0[2] |= p0[2];
    w0[3] |= p0[3];
    w1[0] |= p1[0];
    w1[1] |= p1[1];
    w1[2] |= p1[2];
    w1[3] |= p1[3];
    w2[0]  = o_buf[0];
    w2[1]  = o_buf[1];
    w2[2]  = o_buf[2];
    w2[3]  = o_buf[3];
    w3[0]  = o_buf[4];
    w3[1]  = o_buf[5];
    w3[2]  = o_buf[6];
    w3[3]  = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest);

    w0[0] = P;
    w0[1] = id_buf[0];
    w0[2] = id_buf[1];
    w0[3] = id_buf[2];
    w1[0] = id_buf[3];
    w1[1] = 0x80;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 84 * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, digest);

    // now the RC4 part

    digest[1] = digest[1] & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    rc4_init_40 (S, digest, lid);

    u32 out[4];

    rc4_next_16 (S, 0, 0, padding, out, lid);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_s08 (KERN_ATTR_RULES_ESALT (pdf_t))
{
}

KERNEL_FQ void FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE) m10400_s16 (KERN_ATTR_RULES_ESALT (pdf_t))
{
}
