/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//shared mem too small
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_md4.cl"
#include "inc_hash_md5.cl"
#include "inc_cipher_rc4.cl"
#endif

typedef struct krb5pa
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, u32 *data, u32 *timestamp_ct)
{
  rc4_init_128 (S, data);

  u32 out[4];

  u8 j = 0;

  j = rc4_next_16 (S,  0, j, timestamp_ct + 0, out);

  if ((out[3] & 0xffff0000) != 0x30320000) return 0;

  j = rc4_next_16 (S, 16, j, timestamp_ct + 4, out);

  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0;

  return 1;
}

DECLSPEC void kerb_prepare (const u32 *K, const u32 *checksum, u32 *digest)
{
  // K1=MD5_HMAC(K,1); with 1 encoded as little indian on 4 bytes (01000000 in hexa);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = K[0];
  w0[1] = K[1];
  w0[2] = K[2];
  w0[3] = K[3];
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

  md5_hmac_ctx_t ctx1;

  md5_hmac_init_64 (&ctx1, w0, w1, w2, w3);

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
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

  md5_hmac_update_64 (&ctx1, w0, w1, w2, w3, 4);

  md5_hmac_final (&ctx1);

  w0[0] = ctx1.opad.h[0];
  w0[1] = ctx1.opad.h[1];
  w0[2] = ctx1.opad.h[2];
  w0[3] = ctx1.opad.h[3];
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

  w0[0] = checksum[0];
  w0[1] = checksum[1];
  w0[2] = checksum[2];
  w0[3] = checksum[3];
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

  md5_hmac_update_64 (&ctx, w0, w1, w2, w3, 16);

  md5_hmac_final (&ctx);

  digest[0] = ctx.opad.h[0];
  digest[1] = ctx.opad.h[1];
  digest[2] = ctx.opad.h[2];
  digest[3] = ctx.opad.h[3];
}

KERNEL_FQ void m07500_mxx (KERN_ATTR_ESALT (krb5pa_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET].checksum[3];

  u32 timestamp_ct[8];

  timestamp_ct[0] = esalt_bufs[DIGESTS_OFFSET].timestamp[0];
  timestamp_ct[1] = esalt_bufs[DIGESTS_OFFSET].timestamp[1];
  timestamp_ct[2] = esalt_bufs[DIGESTS_OFFSET].timestamp[2];
  timestamp_ct[3] = esalt_bufs[DIGESTS_OFFSET].timestamp[3];
  timestamp_ct[4] = esalt_bufs[DIGESTS_OFFSET].timestamp[4];
  timestamp_ct[5] = esalt_bufs[DIGESTS_OFFSET].timestamp[5];
  timestamp_ct[6] = esalt_bufs[DIGESTS_OFFSET].timestamp[6];
  timestamp_ct[7] = esalt_bufs[DIGESTS_OFFSET].timestamp[7];

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    md4_update_global_utf16le (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md4_final (&ctx);

    u32 digest[4];

    kerb_prepare (ctx.h, checksum, digest);

    if (decrypt_and_check (S, digest, timestamp_ct) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS, digests_cnt, 0, DIGESTS_OFFSET + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ void m07500_sxx (KERN_ATTR_ESALT (krb5pa_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET].checksum[3];

  u32 timestamp_ct[8];

  timestamp_ct[0] = esalt_bufs[DIGESTS_OFFSET].timestamp[0];
  timestamp_ct[1] = esalt_bufs[DIGESTS_OFFSET].timestamp[1];
  timestamp_ct[2] = esalt_bufs[DIGESTS_OFFSET].timestamp[2];
  timestamp_ct[3] = esalt_bufs[DIGESTS_OFFSET].timestamp[3];
  timestamp_ct[4] = esalt_bufs[DIGESTS_OFFSET].timestamp[4];
  timestamp_ct[5] = esalt_bufs[DIGESTS_OFFSET].timestamp[5];
  timestamp_ct[6] = esalt_bufs[DIGESTS_OFFSET].timestamp[6];
  timestamp_ct[7] = esalt_bufs[DIGESTS_OFFSET].timestamp[7];

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    md4_update_global_utf16le (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md4_final (&ctx);

    u32 digest[4];

    kerb_prepare (ctx.h, checksum, digest);

    if (decrypt_and_check (S, digest, timestamp_ct) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS, digests_cnt, 0, DIGESTS_OFFSET + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
