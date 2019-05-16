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
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
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

KERNEL_FQ void m09800_m04 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
   * shared
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

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
   * esalt
   */

  const u32 version = esalt_bufs[digests_offset].version;

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[digests_offset].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[digests_offset].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[digests_offset].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[digests_offset].encryptedVerifier[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha1
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_salt_len = (out_len * 2) + 16;

    w3[3] = pw_salt_len * 8;
    w3[2] = 0;
    w3[1] = hc_swap32 (w2[1]);
    w3[0] = hc_swap32 (w2[0]);
    w2[3] = hc_swap32 (w1[3]);
    w2[2] = hc_swap32 (w1[2]);
    w2[1] = hc_swap32 (w1[1]);
    w2[0] = hc_swap32 (w1[0]);
    w1[3] = hc_swap32 (w0[3]);
    w1[2] = hc_swap32 (w0[2]);
    w1[1] = hc_swap32 (w0[1]);
    w1[0] = hc_swap32 (w0[0]);
    w0[3] = salt_buf[3];
    w0[2] = salt_buf[2];
    w0[1] = salt_buf[1];
    w0[0] = salt_buf[0];

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = 0;
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
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    if (version == 3)
    {
      digest[1] &= 0xff;
      digest[2]  = 0;
      digest[3]  = 0;
    }

    rc4_init_16 (rc4_key, digest);

    u32 out[4];

    u8 j = rc4_next_16 (rc4_key, 0, 0, encryptedVerifier, out);

    w0[0] = hc_swap32 (out[0]);
    w0[1] = hc_swap32 (out[1]);
    w0[2] = hc_swap32 (out[2]);
    w0[3] = hc_swap32 (out[3]);
    w1[0] = 0x80000000;
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
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (rc4_key, 16, j, digest, out);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void m09800_m08 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_m16 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_s04 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
   * shared
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

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
   * esalt
   */

  const u32 version = esalt_bufs[digests_offset].version;

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[digests_offset].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[digests_offset].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[digests_offset].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[digests_offset].encryptedVerifier[3];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha1
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_salt_len = (out_len * 2) + 16;

    w3[3] = pw_salt_len * 8;
    w3[2] = 0;
    w3[1] = hc_swap32 (w2[1]);
    w3[0] = hc_swap32 (w2[0]);
    w2[3] = hc_swap32 (w1[3]);
    w2[2] = hc_swap32 (w1[2]);
    w2[1] = hc_swap32 (w1[1]);
    w2[0] = hc_swap32 (w1[0]);
    w1[3] = hc_swap32 (w0[3]);
    w1[2] = hc_swap32 (w0[2]);
    w1[1] = hc_swap32 (w0[1]);
    w1[0] = hc_swap32 (w0[0]);
    w0[3] = salt_buf[3];
    w0[2] = salt_buf[2];
    w0[1] = salt_buf[1];
    w0[0] = salt_buf[0];

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = 0;
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
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    if (version == 3)
    {
      digest[1] &= 0xff;
      digest[2]  = 0;
      digest[3]  = 0;
    }

    rc4_init_16 (rc4_key, digest);

    u32 out[4];

    u8 j = rc4_next_16 (rc4_key, 0, 0, encryptedVerifier, out);

    w0[0] = hc_swap32 (out[0]);
    w0[1] = hc_swap32 (out[1]);
    w0[2] = hc_swap32 (out[2]);
    w0[3] = hc_swap32 (out[3]);
    w1[0] = 0x80000000;
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
    w3[3] = 16 * 8;

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, digest);

    digest[0] = hc_swap32_S (digest[0]);
    digest[1] = hc_swap32_S (digest[1]);
    digest[2] = hc_swap32_S (digest[2]);
    digest[3] = hc_swap32_S (digest[3]);

    rc4_next_16 (rc4_key, 16, j, digest, out);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ void m09800_s08 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}

KERNEL_FQ void m09800_s16 (KERN_ATTR_RULES_ESALT (oldoffice34_t))
{
}
