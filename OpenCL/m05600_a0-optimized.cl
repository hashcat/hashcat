/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

DECLSPEC void hmac_md5_pad (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_md5_run (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m05600_m04 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  LOCAL_VK u32 s_userdomain_buf[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].userdomain_buf[i];
  }

  LOCAL_VK u32 s_chall_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].chall_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  const u32 userdomain_len = esalt_bufs[DIGESTS_OFFSET_HOST].user_len
                           + esalt_bufs[DIGESTS_OFFSET_HOST].domain_len;

  const u32 chall_len = esalt_bufs[DIGESTS_OFFSET_HOST].srvchall_len
                      + esalt_bufs[DIGESTS_OFFSET_HOST].clichall_len;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

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

    append_0x80_2x4_VV (w0, w1, out_len);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    w3_t[2] = out_len * 8 * 2;
    w3_t[3] = 0;

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_M_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

KERNEL_FQ void m05600_m08 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
}

KERNEL_FQ void m05600_m16 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
}

KERNEL_FQ void m05600_s04 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  LOCAL_VK u32 s_userdomain_buf[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].userdomain_buf[i];
  }

  LOCAL_VK u32 s_chall_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].chall_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  const u32 userdomain_len = esalt_bufs[DIGESTS_OFFSET_HOST].user_len
                           + esalt_bufs[DIGESTS_OFFSET_HOST].domain_len;

  const u32 chall_len = esalt_bufs[DIGESTS_OFFSET_HOST].srvchall_len
                      + esalt_bufs[DIGESTS_OFFSET_HOST].clichall_len;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

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

    append_0x80_2x4_VV (w0, w1, out_len);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    w3_t[2] = out_len * 8 * 2;
    w3_t[3] = 0;

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
    w1_t[0] = 0;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform_vector (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_S_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

KERNEL_FQ void m05600_s08 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
}

KERNEL_FQ void m05600_s16 (KERN_ATTR_RULES_ESALT (netntlm_t))
{
}
