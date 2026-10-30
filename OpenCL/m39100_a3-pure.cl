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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#endif

typedef struct krb5tgs_1
{
  u32 user[32];
  u32 realm[32];

  u32 salt_buf[32];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_1_t;

DECLSPEC bool krb5_des_crc_encpart_check (PRIVATE_AS const u32 *key, GLOBAL_AS const u32 *checksum, GLOBAL_AS const u32 *edata2, const u32 edata2_len, const bool is_rep, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  u32 c[2];
  u32 p[2];

  // early reject: decrypt block at bytes 8-15 (checksum[2..3], chained from checksum[0..1])
  // etype 1 uses IV=key, so block 0 ciphertext = checksum[0..1] is the CBC chain for block 1

  c[0] = checksum[2];
  c[1] = checksum[3];

  _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

  p[0] ^= checksum[0];
  p[1] ^= checksum[1];

  // p[1] bytes 12-15: start of ASN.1 message
  if (is_rep == false)
  {
    if ((p[1] & 0xff00ffff) != 0x30008163 && (p[1] & 0x0000ffff) != 0x00008263)
      return false;
  }
  else
  {
    if ((p[1] & 0x00ff80ff) != 0x00300079 &&
        (p[1] & 0x00ff80ff) != 0x0030007a &&
        (p[1] & 0xff00ffff) != 0x30008179 &&
        (p[1] & 0xff00ffff) != 0x3000817a)
      return false;
  }

  // full decrypt with IV=key and incremental CRC32 verification

  u32 iv[2];
  u32 stored_crc = 0;
  u32 crc_state = 0;
  u32 block_buf[2];

  iv[0] = key[0];
  iv[1] = key[1];

  const u32 plain_len = 16 + edata2_len;

  for (u32 off = 0; off < plain_len; off += 8)
  {
    if (off < 16)
    {
      c[0] = checksum[(off / 4) + 0];
      c[1] = checksum[(off / 4) + 1];
    }
    else
    {
      c[0] = edata2[((off - 16) / 4) + 0];
      c[1] = edata2[((off - 16) / 4) + 1];
    }

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= iv[0];
    p[1] ^= iv[1];

    iv[0] = c[0];
    iv[1] = c[1];

    if (off == 8)
    {
      stored_crc = p[0];
      p[0] = 0;
    }

    block_buf[0] = p[0];
    block_buf[1] = p[1];

    crc_state = ~crc32 (block_buf, 8, ~crc_state);
  }

  if (crc_state != stored_crc) return false;

  return true;
}

KERNEL_FQ KERNEL_FA void m39100_mxx (KERN_ATTR_VECTOR_ESALT (krb5tgs_1_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 pw[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  const u32 w0l = pw[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw[0] = w0l | words_buf_r[il_pos];

    u32 w[64];

    krb5_des_build_buf (pw, pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_crc_encpart_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].checksum, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, false, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m39100_sxx (KERN_ATTR_VECTOR_ESALT (krb5tgs_1_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 pw[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  const u32 w0l = pw[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw[0] = w0l | words_buf_r[il_pos];

    u32 w[64];

    krb5_des_build_buf (pw, pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_crc_encpart_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].checksum, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, false, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
