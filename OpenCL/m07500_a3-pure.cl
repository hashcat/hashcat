/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//shared mem too small
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#define RC4_USE_BITWISE_ADDRESSING
#define RC4_INIT_128_PREFETCH
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#undef RC4_INIT_128_PREFETCH
#undef RC4_USE_BITWISE_ADDRESSING
#endif

typedef struct krb5pa
{
  u32 user[128];
  u32 realm[128];
  u32 raw_token[64];
  u32 enc_timestamp[16];
  u32 checksum[4];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_t;

DECLSPEC void hmac_md5_pad (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *ipad, PRIVATE_AS u32 *opad)
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

DECLSPEC void hmac_md5_run (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *ipad, PRIVATE_AS u32 *opad, PRIVATE_AS u32 *digest)
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

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, PRIVATE_AS u32 *timestamp_ct, const u64 lid)
{
  rc4_init_128 (S, data, lid);

  // The plaintext opens with an eight byte confounder and a six byte ASN.1 header, and the first
  // bytes tested are the two that start the year. The fourteen keystream bytes ahead of them are
  // never looked at, so those steps only move the S box, and the two after them each get a chance
  // to reject before the next is made.

  u8 a = 0;
  u8 b = 0;

  #define RC4_STEP_DISCARD()             \
  {                                      \
    a += 1;                              \
    const u8 Sa = GET_KEY8 (S, a, lid);  \
    b += Sa;                             \
    const u8 Sb = GET_KEY8 (S, b, lid);  \
    SET_KEY8 (S, a, Sb, lid);            \
    SET_KEY8 (S, b, Sa, lid);            \
  }

  #define RC4_STEP_BYTE(out)             \
  {                                      \
    a += 1;                              \
    const u8 Sa = GET_KEY8 (S, a, lid);  \
    b += Sa;                             \
    const u8 Sb = GET_KEY8 (S, b, lid);  \
    SET_KEY8 (S, a, Sb, lid);            \
    SET_KEY8 (S, b, Sa, lid);            \
    const u8 idx = Sa + Sb;              \
    out = GET_KEY8 (S, idx, lid);        \
  }

  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();
  RC4_STEP_DISCARD ();

  u8 tmp;

  RC4_STEP_BYTE (tmp);

  if ((((u32) tmp ^ (timestamp_ct[3] >> 16)) & 0xff) != 0x32) return 0;

  RC4_STEP_BYTE (tmp);

  if ((((u32) tmp ^ (timestamp_ct[3] >> 24)) & 0xff) != 0x30) return 0;

  #undef RC4_STEP_BYTE
  #undef RC4_STEP_DISCARD

  u32 out[4];

  rc4_next_16 (S, 16, b, timestamp_ct + 4, out, lid);

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

DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *K, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest)
{
  // Everything from the NT hash on has a fixed size whatever the password is, so each HMAC is two
  // bare transforms for the pads and two for the message.

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 ipad[4];
  u32 opad[4];

  // K1 = HMAC-MD5 (K, 1), the key usage number as four little endian bytes

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

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  w0[0] = 1;
  w0[1] = 0x80;
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
  w3[2] = (64 + 4) * 8;
  w3[3] = 0;

  hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

  // K3 = HMAC-MD5 (K1, checksum)

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
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

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  w0[0] = checksum[0];
  w0[1] = checksum[1];
  w0[2] = checksum[2];
  w0[3] = checksum[3];
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

  hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);
}

// The single MD4 block of a password of up to 27 plain ASCII characters, widened to UTF-16 and
// padded. In a mask attack only the first word of the candidate changes, so the block is built
// once for a base word, without that word's varying characters, and the loop ORs those in. Returns
// 0 for a base word that has to take the streaming path.

DECLSPEC int kerb_nt_block (PRIVATE_AS const u32 *w, const u32 pw_len, PRIVATE_AS u32 *t0, PRIVATE_AS u32 *t1, PRIVATE_AS u32 *t2, PRIVATE_AS u32 *t3)
{
  if (pw_len > 27) return 0;

  u32 w0[4];
  u32 w1[4];

  w0[0] = hc_bounded_word_le_S (w, 0, (int) pw_len -  0);
  w0[1] = hc_bounded_word_le_S (w, 1, (int) pw_len -  4);
  w0[2] = hc_bounded_word_le_S (w, 2, (int) pw_len -  8);
  w0[3] = hc_bounded_word_le_S (w, 3, (int) pw_len - 12);
  w1[0] = hc_bounded_word_le_S (w, 4, (int) pw_len - 16);
  w1[1] = hc_bounded_word_le_S (w, 5, (int) pw_len - 20);
  w1[2] = hc_bounded_word_le_S (w, 6, (int) pw_len - 24);
  w1[3] = 0;

  const u32 hi = w0[0] | w0[1] | w0[2] | w0[3] | w1[0] | w1[1] | w1[2];

  if ((hi & 0x80808080) != 0) return 0;

  append_0x80_2x4_S (w0, w1, pw_len);

  make_utf16le_S (w1, t2, t3);
  make_utf16le_S (w0, t0, t1);

  t3[2] = pw_len * 8 * 2;
  t3[3] = 0;

  return 1;
}

KERNEL_FQ KERNEL_FA void m07500_mxx (KERN_ATTR_VECTOR_ESALT (krb5pa_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  u32 timestamp_ct[8];

  timestamp_ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[0];
  timestamp_ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[1];
  timestamp_ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[2];
  timestamp_ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[3];
  timestamp_ct[4] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[4];
  timestamp_ct[5] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[5];
  timestamp_ct[6] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[6];
  timestamp_ct[7] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[7];

  /**
   * loop
   */

  u32x w0l = w[0];

  // A candidate whose password fills a single MD4 block is hashed with a bare transform in a loop of
  // its own. The streaming path is kept out of that loop, where it costs speed even when it is never
  // taken, and picks up what is left in a second one: every candidate of a base word that is too
  // long or not plain ASCII, and otherwise the ones the mask gave a byte above 0x7f.

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  const int single = kerb_nt_block (w, pw_len, t0, t1, t2, t3);

  int streamed = (single == 0);

  if (single == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      if ((w0r & 0x80808080) != 0)
      {
        streamed = 1;

        continue;
      }

      // the four characters of the first word, two to a word once they are widened

      u32 a0[4];

      a0[0] = t0[0] | ((w0r >>  0) & 0x000000ff) | ((w0r <<  8) & 0x00ff0000);
      a0[1] = t0[1] | ((w0r >> 16) & 0x000000ff) | ((w0r >>  8) & 0x00ff0000);
      a0[2] = t0[2];
      a0[3] = t0[3];

      u32 K[4];

      K[0] = MD4M_A;
      K[1] = MD4M_B;
      K[2] = MD4M_C;
      K[3] = MD4M_D;

      md4_transform (a0, t1, t2, t3, K);

      u32 digest[4];

      kerb_prepare (K, checksum, digest);

      if (decrypt_and_check (S, digest, timestamp_ct, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }

  if (streamed == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      if ((single == 1) && ((w0r & 0x80808080) == 0)) continue;

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      md4_ctx_t ctx;

      md4_init (&ctx);

      md4_update_utf16le (&ctx, w, pw_len);

      md4_final (&ctx);

      u32 K[4];

      K[0] = ctx.h[0];
      K[1] = ctx.h[1];
      K[2] = ctx.h[2];
      K[3] = ctx.h[3];

      u32 digest[4];

      kerb_prepare (K, checksum, digest);

      if (decrypt_and_check (S, digest, timestamp_ct, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m07500_sxx (KERN_ATTR_VECTOR_ESALT (krb5pa_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  u32 timestamp_ct[8];

  timestamp_ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[0];
  timestamp_ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[1];
  timestamp_ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[2];
  timestamp_ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[3];
  timestamp_ct[4] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[4];
  timestamp_ct[5] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[5];
  timestamp_ct[6] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[6];
  timestamp_ct[7] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[7];

  /**
   * loop
   */

  u32x w0l = w[0];

  // A candidate whose password fills a single MD4 block is hashed with a bare transform in a loop of
  // its own. The streaming path is kept out of that loop, where it costs speed even when it is never
  // taken, and picks up what is left in a second one: every candidate of a base word that is too
  // long or not plain ASCII, and otherwise the ones the mask gave a byte above 0x7f.

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  const int single = kerb_nt_block (w, pw_len, t0, t1, t2, t3);

  int streamed = (single == 0);

  if (single == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      if ((w0r & 0x80808080) != 0)
      {
        streamed = 1;

        continue;
      }

      // the four characters of the first word, two to a word once they are widened

      u32 a0[4];

      a0[0] = t0[0] | ((w0r >>  0) & 0x000000ff) | ((w0r <<  8) & 0x00ff0000);
      a0[1] = t0[1] | ((w0r >> 16) & 0x000000ff) | ((w0r >>  8) & 0x00ff0000);
      a0[2] = t0[2];
      a0[3] = t0[3];

      u32 K[4];

      K[0] = MD4M_A;
      K[1] = MD4M_B;
      K[2] = MD4M_C;
      K[3] = MD4M_D;

      md4_transform (a0, t1, t2, t3, K);

      u32 digest[4];

      kerb_prepare (K, checksum, digest);

      if (decrypt_and_check (S, digest, timestamp_ct, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }

  if (streamed == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      if ((single == 1) && ((w0r & 0x80808080) == 0)) continue;

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      md4_ctx_t ctx;

      md4_init (&ctx);

      md4_update_utf16le (&ctx, w, pw_len);

      md4_final (&ctx);

      u32 K[4];

      K[0] = ctx.h[0];
      K[1] = ctx.h[1];
      K[2] = ctx.h[2];
      K[3] = ctx.h[3];

      u32 digest[4];

      kerb_prepare (K, checksum, digest);

      if (decrypt_and_check (S, digest, timestamp_ct, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}
