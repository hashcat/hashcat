/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

#define MIN_NULL_BYTES 10

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 secondBlockData[8];
  u32 secondBlockLen;
  u32 rc4key[2];

} oldoffice34_t;

typedef struct
{
  u8 S[256];

  u32 wtf_its_faster;

} RC4_KEY;

DECLSPEC void swap (LOCAL_AS RC4_KEY *rc4_key, const u8 i, const u8 j)
{
  u8 tmp;

  tmp           = rc4_key->S[i];
  rc4_key->S[i] = rc4_key->S[j];
  rc4_key->S[j] = tmp;
}

DECLSPEC void rc4_init_16 (LOCAL_AS RC4_KEY *rc4_key, const u32 *data)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  LOCAL_AS u32 *ptr = (LOCAL_AS u32 *) rc4_key->S;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 64; i++)
  {
    *ptr++ = v; v += a;
  }

  u32 j = 0;

  for (u32 i = 0; i < 16; i++)
  {
    u32 idx = i * 16;

    u32 v;

    v = data[0];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[1];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[2];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[3];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;
  }
}

DECLSPEC u8 rc4_next_16 (LOCAL_AS RC4_KEY *rc4_key, u8 i, u8 j, const u32 *in, u32 *out)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u8 idx;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  0;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  8;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 16;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 24;

    out[k] = in[k] ^ xor4;
  }

  return j;
}

DECLSPEC void m09820m (LOCAL_AS RC4_KEY *rc4_keys, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * shared
   */

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * sha1
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = salt_buf[0];
    w0_t[1] = salt_buf[1];
    w0_t[2] = salt_buf[2];
    w0_t[3] = salt_buf[3];
    w1_t[0] = w0lr;
    w1_t[1] = w0[1];
    w1_t[2] = w0[2];
    w1_t[3] = w0[3];
    w2_t[0] = w1[0];
    w2_t[1] = w1[1];
    w2_t[2] = w1[2];
    w2_t[3] = w1[3];
    w3_t[0] = w2[0];
    w3_t[1] = w2[1];
    w3_t[2] = 0;
    w3_t[3] = (pw_len + 16) * 8;

    u32 pass_hash[5];

    pass_hash[0] = SHA1M_A;
    pass_hash[1] = SHA1M_B;
    pass_hash[2] = SHA1M_C;
    pass_hash[3] = SHA1M_D;
    pass_hash[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, pass_hash);

    w0_t[0] = pass_hash[0];
    w0_t[1] = pass_hash[1];
    w0_t[2] = pass_hash[2];
    w0_t[3] = pass_hash[3];
    w1_t[0] = pass_hash[4];
    w1_t[1] = 0;
    w1_t[2] = 0x80000000;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    digest[0] = hc_swap32 (digest[0]);
    digest[1] = hc_swap32 (digest[1]) & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    // initial compare

    int digest_pos = find_hash (digest, digests_cnt, &digests_buf[digests_offset]);

    if (digest_pos == -1) continue;

    if (esalt_bufs[digests_offset].secondBlockLen != 0)
    {
      w0[0] = pass_hash[0];
      w0[1] = pass_hash[1];
      w0[2] = pass_hash[2];
      w0[3] = pass_hash[3];
      w1[0] = pass_hash[4];
      w1[1] = 0x01000000;
      w1[2] = 0x80000000;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (20 + 4) * 8;

      digest[0] = SHA1M_A;
      digest[1] = SHA1M_B;
      digest[2] = SHA1M_C;
      digest[3] = SHA1M_D;
      digest[4] = SHA1M_E;

      sha1_transform (w0, w1, w2, w3, digest);

      digest[0] = hc_swap32_S (digest[0]);
      digest[1] = hc_swap32_S (digest[1]);
      digest[2] = 0;
      digest[3] = 0;

      digest[1] &= 0xff; // only 40-bit key

      // second block decrypt:

      rc4_init_16 (rc4_key, digest);

      u32 secondBlockData[4];

      secondBlockData[0] = esalt_bufs[digests_offset].secondBlockData[0];
      secondBlockData[1] = esalt_bufs[digests_offset].secondBlockData[1];
      secondBlockData[2] = esalt_bufs[digests_offset].secondBlockData[2];
      secondBlockData[3] = esalt_bufs[digests_offset].secondBlockData[3];

      u32 out[4];

      u32 j = rc4_next_16 (rc4_key, 0, 0, secondBlockData, out);

      int null_bytes = 0;

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      secondBlockData[0] = esalt_bufs[digests_offset].secondBlockData[4];
      secondBlockData[1] = esalt_bufs[digests_offset].secondBlockData[5];
      secondBlockData[2] = esalt_bufs[digests_offset].secondBlockData[6];
      secondBlockData[3] = esalt_bufs[digests_offset].secondBlockData[7];

      rc4_next_16 (rc4_key, 16, j, secondBlockData, out);

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      if (null_bytes < MIN_NULL_BYTES) continue;
    }

    const u32 final_hash_pos = digests_offset + digest_pos;

    if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
    }
  }
}

DECLSPEC void m09820s (LOCAL_AS RC4_KEY *rc4_keys, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * shared
   */

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * sha1
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = salt_buf[0];
    w0_t[1] = salt_buf[1];
    w0_t[2] = salt_buf[2];
    w0_t[3] = salt_buf[3];
    w1_t[0] = w0lr;
    w1_t[1] = w0[1];
    w1_t[2] = w0[2];
    w1_t[3] = w0[3];
    w2_t[0] = w1[0];
    w2_t[1] = w1[1];
    w2_t[2] = w1[2];
    w2_t[3] = w1[3];
    w3_t[0] = w2[0];
    w3_t[1] = w2[1];
    w3_t[2] = 0;
    w3_t[3] = (pw_len + 16) * 8;

    u32 pass_hash[5];

    pass_hash[0] = SHA1M_A;
    pass_hash[1] = SHA1M_B;
    pass_hash[2] = SHA1M_C;
    pass_hash[3] = SHA1M_D;
    pass_hash[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, pass_hash);

    w0_t[0] = pass_hash[0];
    w0_t[1] = pass_hash[1];
    w0_t[2] = pass_hash[2];
    w0_t[3] = pass_hash[3];
    w1_t[0] = pass_hash[4];
    w1_t[1] = 0;
    w1_t[2] = 0x80000000;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 0;
    w3_t[3] = (20 + 4) * 8;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0_t, w1_t, w2_t, w3_t, digest);

    digest[0] = hc_swap32 (digest[0]);
    digest[1] = hc_swap32 (digest[1]) & 0xff;
    digest[2] = 0;
    digest[3] = 0;

    // initial compare

    if (digest[0] != search[0]) continue;
    if (digest[1] != search[1]) continue;

    if (esalt_bufs[digests_offset].secondBlockLen != 0)
    {
      w0[0] = pass_hash[0];
      w0[1] = pass_hash[1];
      w0[2] = pass_hash[2];
      w0[3] = pass_hash[3];
      w1[0] = pass_hash[4];
      w1[1] = 0x01000000;
      w1[2] = 0x80000000;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (20 + 4) * 8;

      digest[0] = SHA1M_A;
      digest[1] = SHA1M_B;
      digest[2] = SHA1M_C;
      digest[3] = SHA1M_D;
      digest[4] = SHA1M_E;

      sha1_transform (w0, w1, w2, w3, digest);

      digest[0] = hc_swap32_S (digest[0]);
      digest[1] = hc_swap32_S (digest[1]);
      digest[2] = 0;
      digest[3] = 0;

      digest[1] &= 0xff; // only 40-bit key

      // second block decrypt:

      rc4_init_16 (rc4_key, digest);

      u32 secondBlockData[4];

      secondBlockData[0] = esalt_bufs[digests_offset].secondBlockData[0];
      secondBlockData[1] = esalt_bufs[digests_offset].secondBlockData[1];
      secondBlockData[2] = esalt_bufs[digests_offset].secondBlockData[2];
      secondBlockData[3] = esalt_bufs[digests_offset].secondBlockData[3];

      u32 out[4];

      u32 j = rc4_next_16 (rc4_key, 0, 0, secondBlockData, out);

      int null_bytes = 0;

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      secondBlockData[0] = esalt_bufs[digests_offset].secondBlockData[4];
      secondBlockData[1] = esalt_bufs[digests_offset].secondBlockData[5];
      secondBlockData[2] = esalt_bufs[digests_offset].secondBlockData[6];
      secondBlockData[3] = esalt_bufs[digests_offset].secondBlockData[7];

      rc4_next_16 (rc4_key, 16, j, secondBlockData, out);

      for (int k = 0; k < 4; k++)
      {
        if ((out[k] & 0x000000ff) == 0) null_bytes++;
        if ((out[k] & 0x0000ff00) == 0) null_bytes++;
        if ((out[k] & 0x00ff0000) == 0) null_bytes++;
        if ((out[k] & 0xff000000) == 0) null_bytes++;
      }

      if (null_bytes < MIN_NULL_BYTES) continue;
    }

    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ void m09820_m04 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m09820_m08 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m09820_m16 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m09820_s04 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m09820_s08 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m09820_s16 (KERN_ATTR_ESALT (oldoffice34_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  m09820s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
