/**
 * Author......: see docs/credits.txt
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
#include "inc_hash_md4.cl"
#include "inc_hash_md5.cl"
#endif

typedef struct krb5tgs
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_t;

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

DECLSPEC u8 rc4_next_16 (LOCAL_AS RC4_KEY *rc4_key, u8 i, u8 j, GLOBAL_AS const u32 *in, u32 *out)
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

DECLSPEC void hmac_md5_pad (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *ipad, u32 *opad)
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

  md5_transform (w0, w1, w2, w3, ipad);

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

  md5_transform (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_md5_run (u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *ipad, u32 *opad, u32 *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform (w0, w1, w2, w3, digest);

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

  md5_transform (w0, w1, w2, w3, digest);
}

DECLSPEC int decrypt_and_check (LOCAL_AS RC4_KEY *rc4_key, u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, const u32 *K2, const u32 *checksum)
{
  rc4_init_16 (rc4_key, data);

  u32 out0[4];
  u32 out1[4];

  u8 i = 0;
  u8 j = 0;

  /*
    8 first bytes are nonce, then ASN1 structs (DER encoding: type-length-data)

    if length >= 128 bytes:
        length is on 2 bytes and type is \x63\x82 (encode_krb5_enc_tkt_part) and data is an ASN1 sequence \x30\x82
    else:
        length is on 1 byte and type is \x63\x81 and data is an ASN1 sequence \x30\x81

    next headers follow the same ASN1 "type-length-data" scheme
  */

  j = rc4_next_16 (rc4_key, i, j, edata2 + 0, out0); i += 16;

  if (((out0[2] & 0xff00ffff) != 0x30008163) && ((out0[2] & 0x0000ffff) != 0x00008263)) return 0;

  j = rc4_next_16 (rc4_key, i, j, edata2 + 4, out1); i += 16;

  if (((out1[0] & 0x00ffffff) != 0x00000503) && (out1[0] != 0x050307A0)) return 0;

  rc4_init_16 (rc4_key, data);

  i = 0;
  j = 0;

  // init hmac

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = K2[0];
  w0[1] = K2[1];
  w0[2] = K2[2];
  w0[3] = K2[3];
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

  u32 ipad[4];
  u32 opad[4];

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  int edata2_left;

  for (edata2_left = edata2_len; edata2_left >= 64; edata2_left -= 64)
  {
    j = rc4_next_16 (rc4_key, i, j, edata2, w0); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w1); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w2); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w3); i += 16; edata2 += 4;

    md5_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = 0;
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

  if (edata2_left < 16)
  {
    j = rc4_next_16 (rc4_key, i, j, edata2, w0); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w0, edata2_left & 0xf);

    append_0x80_1x4 (w0, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else if (edata2_left < 32)
  {
    j = rc4_next_16 (rc4_key, i, j, edata2, w0); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w1); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w1, edata2_left & 0xf);

    append_0x80_1x4 (w1, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else if (edata2_left < 48)
  {
    j = rc4_next_16 (rc4_key, i, j, edata2, w0); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w1); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w2); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w2, edata2_left & 0xf);

    append_0x80_1x4 (w2, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else
  {
    j = rc4_next_16 (rc4_key, i, j, edata2, w0); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w1); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w2); i += 16; edata2 += 4;
    j = rc4_next_16 (rc4_key, i, j, edata2, w3); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w3, edata2_left & 0xf);

    append_0x80_1x4 (w3, edata2_left & 0xf);

    if (edata2_left < 56)
    {
      w3[2] = (64 + edata2_len) * 8;
      w3[3] = 0;

      md5_transform (w0, w1, w2, w3, ipad);
    }
    else
    {
      md5_transform (w0, w1, w2, w3, ipad);

      w0[0] = 0;
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
      w3[2] = (64 + edata2_len) * 8;
      w3[3] = 0;

      md5_transform (w0, w1, w2, w3, ipad);
    }
  }

  w0[0] = ipad[0];
  w0[1] = ipad[1];
  w0[2] = ipad[2];
  w0[3] = ipad[3];
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

  md5_transform (w0, w1, w2, w3, opad);

  if (checksum[0] != opad[0]) return 0;
  if (checksum[1] != opad[1]) return 0;
  if (checksum[2] != opad[2]) return 0;
  if (checksum[3] != opad[3]) return 0;

  return 1;
}

DECLSPEC void kerb_prepare (const u32 *w0, const u32 *w1, const u32 pw_len, const u32 *checksum, u32 *digest, u32 *K2)
{
  /**
   * pads
   */

  u32 w0_t[4];
  u32 w1_t[4];
  u32 w2_t[4];
  u32 w3_t[4];

  w0_t[0] = w0[0];
  w0_t[1] = w0[1];
  w0_t[2] = w0[2];
  w0_t[3] = w0[3];
  w1_t[0] = w1[0];
  w1_t[1] = w1[1];
  w1_t[2] = w1[2];
  w1_t[3] = w1[3];
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // K=MD4(Little_indian(UNICODE(pwd))

  append_0x80_2x4 (w0_t, w1_t, pw_len);

  make_utf16le (w1_t, w2_t, w3_t);
  make_utf16le (w0_t, w0_t, w1_t);

  w3_t[2] = pw_len * 8 * 2;
  w3_t[3] = 0;

  digest[0] = MD4M_A;
  digest[1] = MD4M_B;
  digest[2] = MD4M_C;
  digest[3] = MD4M_D;

  md4_transform (w0_t, w1_t, w2_t, w3_t, digest);

  // K1=MD5_HMAC(K,1); with 2 encoded as little indian on 4 bytes (02000000 in hexa);

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

  u32 ipad[4];
  u32 opad[4];

  hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

  w0_t[0] = 2;
  w0_t[1] = 0x80;
  w0_t[2] = 0;
  w0_t[3] = 0;
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
  w3_t[2] = (64 + 4) * 8;
  w3_t[3] = 0;

  hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

  // K2 = K1;

  K2[0] = digest[0];
  K2[1] = digest[1];
  K2[2] = digest[2];
  K2[3] = digest[3];

  // K3=MD5_HMAC(K1,checksum);

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

  hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

  w0_t[0] = checksum[0];
  w0_t[1] = checksum[1];
  w0_t[2] = checksum[2];
  w0_t[3] = checksum[3];
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
  w3_t[2] = (64 + 16) * 8;
  w3_t[3] = 0;

  hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);
}

DECLSPEC void m13100 (LOCAL_AS RC4_KEY *rc4_key, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (krb5tgs_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * salt
   */

  u32 checksum[4];

  checksum[0] = esalt_bufs[digests_offset].checksum[0];
  checksum[1] = esalt_bufs[digests_offset].checksum[1];
  checksum[2] = esalt_bufs[digests_offset].checksum[2];
  checksum[3] = esalt_bufs[digests_offset].checksum[3];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 w0r = bfs_buf[il_pos].i;

    w0[0] = w0l | w0r;

    /**
     * kerberos
     */

    u32 digest[4];

    u32 K2[4];

    kerb_prepare (w0, w1, pw_len, checksum, digest, K2);

    u32 tmp[4];

    tmp[0] = digest[0];
    tmp[1] = digest[1];
    tmp[2] = digest[2];
    tmp[3] = digest[3];

    if (decrypt_and_check (rc4_key, tmp, esalt_bufs[digests_offset].edata2, esalt_bufs[digests_offset].edata2_len, K2, checksum) == 1)
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ void m13100_m04 (KERN_ATTR_ESALT (krb5tgs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  m13100 (rc4_key, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m13100_m08 (KERN_ATTR_ESALT (krb5tgs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  m13100 (rc4_key, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m13100_m16 (KERN_ATTR_ESALT (krb5tgs_t))
{
}

KERNEL_FQ void m13100_s04 (KERN_ATTR_ESALT (krb5tgs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  m13100 (rc4_key, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m13100_s08 (KERN_ATTR_ESALT (krb5tgs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  m13100 (rc4_key, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m13100_s16 (KERN_ATTR_ESALT (krb5tgs_t))
{
}
