/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"

typedef struct
{
  u8 S[256];

  u32 wtf_its_faster;

} RC4_KEY;

DECLSPEC void swap (__local RC4_KEY *rc4_key, const u8 i, const u8 j)
{
  u8 tmp;

  tmp           = rc4_key->S[i];
  rc4_key->S[i] = rc4_key->S[j];
  rc4_key->S[j] = tmp;
}

DECLSPEC void rc4_init_16 (__local RC4_KEY *rc4_key, const u32 *data)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  __local u32 *ptr = (__local u32 *) rc4_key->S;

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

DECLSPEC u8 rc4_next_16 (__local RC4_KEY *rc4_key, u8 i, u8 j, const u32 *in, u32 *out)
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

DECLSPEC void m09700m (__local RC4_KEY *rc4_keys, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * shared
   */

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * salt
   */

  u32 salt_buf_t0[4];

  salt_buf_t0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf_t0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf_t0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf_t0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf_t1[5];

  salt_buf_t1[0] =                        salt_buf_t0[0] <<  8;
  salt_buf_t1[1] = salt_buf_t0[0] >> 24 | salt_buf_t0[1] <<  8;
  salt_buf_t1[2] = salt_buf_t0[1] >> 24 | salt_buf_t0[2] <<  8;
  salt_buf_t1[3] = salt_buf_t0[2] >> 24 | salt_buf_t0[3] <<  8;
  salt_buf_t1[4] = salt_buf_t0[3] >> 24;

  u32 salt_buf_t2[5];

  salt_buf_t2[0] =                        salt_buf_t0[0] << 16;
  salt_buf_t2[1] = salt_buf_t0[0] >> 16 | salt_buf_t0[1] << 16;
  salt_buf_t2[2] = salt_buf_t0[1] >> 16 | salt_buf_t0[2] << 16;
  salt_buf_t2[3] = salt_buf_t0[2] >> 16 | salt_buf_t0[3] << 16;
  salt_buf_t2[4] = salt_buf_t0[3] >> 16;

  u32 salt_buf_t3[5];

  salt_buf_t3[0] =                        salt_buf_t0[0] << 24;
  salt_buf_t3[1] = salt_buf_t0[0] >>  8 | salt_buf_t0[1] << 24;
  salt_buf_t3[2] = salt_buf_t0[1] >>  8 | salt_buf_t0[2] << 24;
  salt_buf_t3[3] = salt_buf_t0[2] >>  8 | salt_buf_t0[3] << 24;
  salt_buf_t3[4] = salt_buf_t0[3] >>  8;

  const u32 salt_len = 16;

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    const u32 w0lr = w0l | w0r;

    /**
     * md5
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = pw_len * 8;
    w3_t[3] = 0;

    u32 digest_t0[4];
    u32 digest_t1[2]; // need only first 5 byte
    u32 digest_t2[2];
    u32 digest_t3[2];

    digest_t0[0] = MD5M_A;
    digest_t0[1] = MD5M_B;
    digest_t0[2] = MD5M_C;
    digest_t0[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest_t0);

    // prepare 16 * 21 buffer stuff

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    // offsets

    digest_t0[0] &= 0xffffffff;
    digest_t0[1] &= 0x000000ff;
    digest_t0[2] &= 0x00000000;
    digest_t0[3] &= 0x00000000;

    digest_t1[0] =                      digest_t0[0] <<  8;
    digest_t1[1] = digest_t0[0] >> 24 | digest_t0[1] <<  8;

    digest_t2[0] =                      digest_t0[0] << 16;
    digest_t2[1] = digest_t0[0] >> 16 | digest_t0[1] << 16;

    digest_t3[0] =                      digest_t0[0] << 24;
    digest_t3[1] = digest_t0[0] >>  8 | digest_t0[1] << 24;

    // generate the 16 * 21 buffer

    // 0..5
    w0_t[0]  = digest_t0[0];
    w0_t[1]  = digest_t0[1];

    // 5..21
    w0_t[1] |= salt_buf_t1[0];
    w0_t[2]  = salt_buf_t1[1];
    w0_t[3]  = salt_buf_t1[2];
    w1_t[0]  = salt_buf_t1[3];
    w1_t[1]  = salt_buf_t1[4];

    // 21..26
    w1_t[1] |= digest_t1[0];
    w1_t[2]  = digest_t1[1];

    // 26..42
    w1_t[2] |= salt_buf_t2[0];
    w1_t[3]  = salt_buf_t2[1];
    w2_t[0]  = salt_buf_t2[2];
    w2_t[1]  = salt_buf_t2[3];
    w2_t[2]  = salt_buf_t2[4];

    // 42..47
    w2_t[2] |= digest_t2[0];
    w2_t[3]  = digest_t2[1];

    // 47..63
    w2_t[3] |= salt_buf_t3[0];
    w3_t[0]  = salt_buf_t3[1];
    w3_t[1]  = salt_buf_t3[2];
    w3_t[2]  = salt_buf_t3[3];
    w3_t[3]  = salt_buf_t3[4];

    // 63..

    w3_t[3] |= digest_t3[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..4
    w0_t[0]  = digest_t3[1];

    // 4..20
    w0_t[1]  = salt_buf_t0[0];
    w0_t[2]  = salt_buf_t0[1];
    w0_t[3]  = salt_buf_t0[2];
    w1_t[0]  = salt_buf_t0[3];

    // 20..25
    w1_t[1]  = digest_t0[0];
    w1_t[2]  = digest_t0[1];

    // 25..41
    w1_t[2] |= salt_buf_t1[0];
    w1_t[3]  = salt_buf_t1[1];
    w2_t[0]  = salt_buf_t1[2];
    w2_t[1]  = salt_buf_t1[3];
    w2_t[2]  = salt_buf_t1[4];

    // 41..46
    w2_t[2] |= digest_t1[0];
    w2_t[3]  = digest_t1[1];

    // 46..62
    w2_t[3] |= salt_buf_t2[0];
    w3_t[0]  = salt_buf_t2[1];
    w3_t[1]  = salt_buf_t2[2];
    w3_t[2]  = salt_buf_t2[3];
    w3_t[3]  = salt_buf_t2[4];

    // 62..
    w3_t[3] |= digest_t2[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..3
    w0_t[0]  = digest_t2[1];

    // 3..19
    w0_t[0] |= salt_buf_t3[0];
    w0_t[1]  = salt_buf_t3[1];
    w0_t[2]  = salt_buf_t3[2];
    w0_t[3]  = salt_buf_t3[3];
    w1_t[0]  = salt_buf_t3[4];

    // 19..24
    w1_t[0] |= digest_t3[0];
    w1_t[1]  = digest_t3[1];

    // 24..40
    w1_t[2]  = salt_buf_t0[0];
    w1_t[3]  = salt_buf_t0[1];
    w2_t[0]  = salt_buf_t0[2];
    w2_t[1]  = salt_buf_t0[3];

    // 40..45
    w2_t[2]  = digest_t0[0];
    w2_t[3]  = digest_t0[1];

    // 45..61
    w2_t[3] |= salt_buf_t1[0];
    w3_t[0]  = salt_buf_t1[1];
    w3_t[1]  = salt_buf_t1[2];
    w3_t[2]  = salt_buf_t1[3];
    w3_t[3]  = salt_buf_t1[4];

    // 61..
    w3_t[3] |= digest_t1[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..2
    w0_t[0]  = digest_t1[1];

    // 2..18
    w0_t[0] |= salt_buf_t2[0];
    w0_t[1]  = salt_buf_t2[1];
    w0_t[2]  = salt_buf_t2[2];
    w0_t[3]  = salt_buf_t2[3];
    w1_t[0]  = salt_buf_t2[4];

    // 18..23
    w1_t[0] |= digest_t2[0];
    w1_t[1]  = digest_t2[1];

    // 23..39
    w1_t[1] |= salt_buf_t3[0];
    w1_t[2]  = salt_buf_t3[1];
    w1_t[3]  = salt_buf_t3[2];
    w2_t[0]  = salt_buf_t3[3];
    w2_t[1]  = salt_buf_t3[4];

    // 39..44
    w2_t[1] |= digest_t3[0];
    w2_t[2]  = digest_t3[1];

    // 44..60
    w2_t[3]  = salt_buf_t0[0];
    w3_t[0]  = salt_buf_t0[1];
    w3_t[1]  = salt_buf_t0[2];
    w3_t[2]  = salt_buf_t0[3];

    // 60..
    w3_t[3]  = digest_t0[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..1
    w0_t[0]  = digest_t0[1];

    // 1..17
    w0_t[0] |= salt_buf_t1[0];
    w0_t[1]  = salt_buf_t1[1];
    w0_t[2]  = salt_buf_t1[2];
    w0_t[3]  = salt_buf_t1[3];
    w1_t[0]  = salt_buf_t1[4];

    // 17..22
    w1_t[0] |= digest_t1[0];
    w1_t[1]  = digest_t1[1];

    // 22..38
    w1_t[1] |= salt_buf_t2[0];
    w1_t[2]  = salt_buf_t2[1];
    w1_t[3]  = salt_buf_t2[2];
    w2_t[0]  = salt_buf_t2[3];
    w2_t[1]  = salt_buf_t2[4];

    // 38..43
    w2_t[1] |= digest_t2[0];
    w2_t[2]  = digest_t2[1];

    // 43..59
    w2_t[2] |= salt_buf_t3[0];
    w2_t[3]  = salt_buf_t3[1];
    w3_t[0]  = salt_buf_t3[2];
    w3_t[1]  = salt_buf_t3[3];
    w3_t[2]  = salt_buf_t3[4];

    // 59..
    w3_t[2] |= digest_t3[0];
    w3_t[3]  = digest_t3[1];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0]  = salt_buf_t0[0];
    w0_t[1]  = salt_buf_t0[1];
    w0_t[2]  = salt_buf_t0[2];
    w0_t[3]  = salt_buf_t0[3];
    w1_t[0]  = 0x80;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 21 * 16 * 8;
    w3_t[3]  = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the 40 bit input for the MD5 which then will generate the RC4 key, so it's precomputable!

    w0_t[0]  = digest[0];
    w0_t[1]  = digest[1] & 0xff;
    w0_t[2]  = 0x8000;
    w0_t[3]  = 0;
    w1_t[0]  = 0;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 9 * 8;
    w3_t[3]  = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    rc4_init_16 (rc4_key, digest);

    u32 out[4];

    u8 j = rc4_next_16 (rc4_key, 0, 0, encryptedVerifier, out);

    w0_t[0] = out[0];
    w0_t[1] = out[1];
    w0_t[2] = out[2];
    w0_t[3] = out[3];
    w1_t[0] = 0x80;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 16 * 8;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    rc4_next_16 (rc4_key, 16, j, digest, out);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

DECLSPEC void m09700s (__local RC4_KEY *rc4_keys, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * shared
   */

  __local RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * salt
   */

  u32 salt_buf_t0[4];

  salt_buf_t0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf_t0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf_t0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf_t0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf_t1[5];

  salt_buf_t1[0] =                        salt_buf_t0[0] <<  8;
  salt_buf_t1[1] = salt_buf_t0[0] >> 24 | salt_buf_t0[1] <<  8;
  salt_buf_t1[2] = salt_buf_t0[1] >> 24 | salt_buf_t0[2] <<  8;
  salt_buf_t1[3] = salt_buf_t0[2] >> 24 | salt_buf_t0[3] <<  8;
  salt_buf_t1[4] = salt_buf_t0[3] >> 24;

  u32 salt_buf_t2[5];

  salt_buf_t2[0] =                        salt_buf_t0[0] << 16;
  salt_buf_t2[1] = salt_buf_t0[0] >> 16 | salt_buf_t0[1] << 16;
  salt_buf_t2[2] = salt_buf_t0[1] >> 16 | salt_buf_t0[2] << 16;
  salt_buf_t2[3] = salt_buf_t0[2] >> 16 | salt_buf_t0[3] << 16;
  salt_buf_t2[4] = salt_buf_t0[3] >> 16;

  u32 salt_buf_t3[5];

  salt_buf_t3[0] =                        salt_buf_t0[0] << 24;
  salt_buf_t3[1] = salt_buf_t0[0] >>  8 | salt_buf_t0[1] << 24;
  salt_buf_t3[2] = salt_buf_t0[1] >>  8 | salt_buf_t0[2] << 24;
  salt_buf_t3[3] = salt_buf_t0[2] >>  8 | salt_buf_t0[3] << 24;
  salt_buf_t3[4] = salt_buf_t0[3] >>  8;

  const u32 salt_len = 16;

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    const u32 w0lr = w0l | w0r;

    /**
     * md5
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = pw_len * 8;
    w3_t[3] = 0;

    u32 digest_t0[4];
    u32 digest_t1[2]; // need only first 5 byte
    u32 digest_t2[2];
    u32 digest_t3[2];

    digest_t0[0] = MD5M_A;
    digest_t0[1] = MD5M_B;
    digest_t0[2] = MD5M_C;
    digest_t0[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest_t0);

    // prepare 16 * 21 buffer stuff

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    // offsets

    digest_t0[0] &= 0xffffffff;
    digest_t0[1] &= 0x000000ff;
    digest_t0[2] &= 0x00000000;
    digest_t0[3] &= 0x00000000;

    digest_t1[0] =                      digest_t0[0] <<  8;
    digest_t1[1] = digest_t0[0] >> 24 | digest_t0[1] <<  8;

    digest_t2[0] =                      digest_t0[0] << 16;
    digest_t2[1] = digest_t0[0] >> 16 | digest_t0[1] << 16;

    digest_t3[0] =                      digest_t0[0] << 24;
    digest_t3[1] = digest_t0[0] >>  8 | digest_t0[1] << 24;

    // generate the 16 * 21 buffer

    // 0..5
    w0_t[0]  = digest_t0[0];
    w0_t[1]  = digest_t0[1];

    // 5..21
    w0_t[1] |= salt_buf_t1[0];
    w0_t[2]  = salt_buf_t1[1];
    w0_t[3]  = salt_buf_t1[2];
    w1_t[0]  = salt_buf_t1[3];
    w1_t[1]  = salt_buf_t1[4];

    // 21..26
    w1_t[1] |= digest_t1[0];
    w1_t[2]  = digest_t1[1];

    // 26..42
    w1_t[2] |= salt_buf_t2[0];
    w1_t[3]  = salt_buf_t2[1];
    w2_t[0]  = salt_buf_t2[2];
    w2_t[1]  = salt_buf_t2[3];
    w2_t[2]  = salt_buf_t2[4];

    // 42..47
    w2_t[2] |= digest_t2[0];
    w2_t[3]  = digest_t2[1];

    // 47..63
    w2_t[3] |= salt_buf_t3[0];
    w3_t[0]  = salt_buf_t3[1];
    w3_t[1]  = salt_buf_t3[2];
    w3_t[2]  = salt_buf_t3[3];
    w3_t[3]  = salt_buf_t3[4];

    // 63..

    w3_t[3] |= digest_t3[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..4
    w0_t[0]  = digest_t3[1];

    // 4..20
    w0_t[1]  = salt_buf_t0[0];
    w0_t[2]  = salt_buf_t0[1];
    w0_t[3]  = salt_buf_t0[2];
    w1_t[0]  = salt_buf_t0[3];

    // 20..25
    w1_t[1]  = digest_t0[0];
    w1_t[2]  = digest_t0[1];

    // 25..41
    w1_t[2] |= salt_buf_t1[0];
    w1_t[3]  = salt_buf_t1[1];
    w2_t[0]  = salt_buf_t1[2];
    w2_t[1]  = salt_buf_t1[3];
    w2_t[2]  = salt_buf_t1[4];

    // 41..46
    w2_t[2] |= digest_t1[0];
    w2_t[3]  = digest_t1[1];

    // 46..62
    w2_t[3] |= salt_buf_t2[0];
    w3_t[0]  = salt_buf_t2[1];
    w3_t[1]  = salt_buf_t2[2];
    w3_t[2]  = salt_buf_t2[3];
    w3_t[3]  = salt_buf_t2[4];

    // 62..
    w3_t[3] |= digest_t2[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..3
    w0_t[0]  = digest_t2[1];

    // 3..19
    w0_t[0] |= salt_buf_t3[0];
    w0_t[1]  = salt_buf_t3[1];
    w0_t[2]  = salt_buf_t3[2];
    w0_t[3]  = salt_buf_t3[3];
    w1_t[0]  = salt_buf_t3[4];

    // 19..24
    w1_t[0] |= digest_t3[0];
    w1_t[1]  = digest_t3[1];

    // 24..40
    w1_t[2]  = salt_buf_t0[0];
    w1_t[3]  = salt_buf_t0[1];
    w2_t[0]  = salt_buf_t0[2];
    w2_t[1]  = salt_buf_t0[3];

    // 40..45
    w2_t[2]  = digest_t0[0];
    w2_t[3]  = digest_t0[1];

    // 45..61
    w2_t[3] |= salt_buf_t1[0];
    w3_t[0]  = salt_buf_t1[1];
    w3_t[1]  = salt_buf_t1[2];
    w3_t[2]  = salt_buf_t1[3];
    w3_t[3]  = salt_buf_t1[4];

    // 61..
    w3_t[3] |= digest_t1[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..2
    w0_t[0]  = digest_t1[1];

    // 2..18
    w0_t[0] |= salt_buf_t2[0];
    w0_t[1]  = salt_buf_t2[1];
    w0_t[2]  = salt_buf_t2[2];
    w0_t[3]  = salt_buf_t2[3];
    w1_t[0]  = salt_buf_t2[4];

    // 18..23
    w1_t[0] |= digest_t2[0];
    w1_t[1]  = digest_t2[1];

    // 23..39
    w1_t[1] |= salt_buf_t3[0];
    w1_t[2]  = salt_buf_t3[1];
    w1_t[3]  = salt_buf_t3[2];
    w2_t[0]  = salt_buf_t3[3];
    w2_t[1]  = salt_buf_t3[4];

    // 39..44
    w2_t[1] |= digest_t3[0];
    w2_t[2]  = digest_t3[1];

    // 44..60
    w2_t[3]  = salt_buf_t0[0];
    w3_t[0]  = salt_buf_t0[1];
    w3_t[1]  = salt_buf_t0[2];
    w3_t[2]  = salt_buf_t0[3];

    // 60..
    w3_t[3]  = digest_t0[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..1
    w0_t[0]  = digest_t0[1];

    // 1..17
    w0_t[0] |= salt_buf_t1[0];
    w0_t[1]  = salt_buf_t1[1];
    w0_t[2]  = salt_buf_t1[2];
    w0_t[3]  = salt_buf_t1[3];
    w1_t[0]  = salt_buf_t1[4];

    // 17..22
    w1_t[0] |= digest_t1[0];
    w1_t[1]  = digest_t1[1];

    // 22..38
    w1_t[1] |= salt_buf_t2[0];
    w1_t[2]  = salt_buf_t2[1];
    w1_t[3]  = salt_buf_t2[2];
    w2_t[0]  = salt_buf_t2[3];
    w2_t[1]  = salt_buf_t2[4];

    // 38..43
    w2_t[1] |= digest_t2[0];
    w2_t[2]  = digest_t2[1];

    // 43..59
    w2_t[2] |= salt_buf_t3[0];
    w2_t[3]  = salt_buf_t3[1];
    w3_t[0]  = salt_buf_t3[2];
    w3_t[1]  = salt_buf_t3[3];
    w3_t[2]  = salt_buf_t3[4];

    // 59..
    w3_t[2] |= digest_t3[0];
    w3_t[3]  = digest_t3[1];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0]  = salt_buf_t0[0];
    w0_t[1]  = salt_buf_t0[1];
    w0_t[2]  = salt_buf_t0[2];
    w0_t[3]  = salt_buf_t0[3];
    w1_t[0]  = 0x80;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 21 * 16 * 8;
    w3_t[3]  = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the 40 bit input for the MD5 which then will generate the RC4 key, so it's precomputable!

    w0_t[0]  = digest[0];
    w0_t[1]  = digest[1] & 0xff;
    w0_t[2]  = 0x8000;
    w0_t[3]  = 0;
    w1_t[0]  = 0;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 9 * 8;
    w3_t[3]  = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    rc4_init_16 (rc4_key, digest);

    u32 out[4];

    u8 j = rc4_next_16 (rc4_key, 0, 0, encryptedVerifier, out);

    w0_t[0] = out[0];
    w0_t[1] = out[1];
    w0_t[2] = out[2];
    w0_t[3] = out[3];
    w1_t[0] = 0x80;
    w1_t[1] = 0;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 16 * 8;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    rc4_next_16 (rc4_key, 16, j, digest, out);

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_m04 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_m08 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_m16 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700m (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_s04 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_s08 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void __attribute__((reqd_work_group_size(64, 1, 1))) m09700_s16 (KERN_ATTR_ESALT (oldoffice01_t))
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

  __local RC4_KEY rc4_keys[64];

  m09700s (rc4_keys, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
