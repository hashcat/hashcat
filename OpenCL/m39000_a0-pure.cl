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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#endif

typedef struct krb5pa_3
{
  u32 user[32];
  u32 realm[32];

  u32 salt_buf[32];
  u32 salt_len;

  u32 enc_timestamp[32];
  u32 enc_timestamp_len;

} krb5pa_3_t;

DECLSPEC bool krb5_des_pa_timestamp_check (PRIVATE_AS const u32 *key, GLOBAL_AS const u32 *enc_timestamp, const u32 enc_timestamp_len, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  // DES-CBC decrypt the entire timestamp with IV=0

  md5_ctx_t ctx;

  md5_init (&ctx);

  u32 iv[2];
  u32 mac[4];
  u32 w[16];

  u32 pos = 0;
  u32 ts_check_word = 0;
  bool ts_seen = false;

  iv[0] = 0;
  iv[1] = 0;

  for (u32 off = 0; off < enc_timestamp_len; off += 8)
  {
    u32 c[2];
    u32 p[2];

    c[0] = enc_timestamp[(off / 4) + 0];
    c[1] = enc_timestamp[(off / 4) + 1];

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= iv[0];
    p[1] ^= iv[1];

    iv[0] = c[0];
    iv[1] = c[1];

    // bytes 8-23: MD5 checksum: extract then zero for MD5 recomputation
    if (off == 8)
    {
      mac[0] = p[0];
      mac[1] = p[1];
      p[0] = 0;
      p[1] = 0;
    }
    else if (off == 16)
    {
      mac[2] = p[0];
      mac[3] = p[1];
      p[0] = 0;
      p[1] = 0;
    }

    // byte 24 starts the PA-ENC-TS-ENC: check for SEQUENCE tag 0x30 and
    // a GeneralizedTime starting with "20" (0x3230)
    if (off == 24 && !ts_seen)
    {
      // p[0] should start with 0x30 (SEQUENCE) at its first byte
      if ((p[0] & 0x000000ff) != 0x00000030) return false;

      ts_seen = true;
    }

    w[pos + 0] = p[0];
    w[pos + 1] = p[1];

    pos += 2;

    if (pos == 16)
    {
      md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, 64);
      pos = 0;
    }
  }

  if (pos != 0)
  {
    for (u32 i = pos; i < 16; i++) w[i] = 0;

    md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, pos * 4);
  }

  md5_final (&ctx);

  if (mac[0] != ctx.h[0]) return false;
  if (mac[1] != ctx.h[1]) return false;
  if (mac[2] != ctx.h[2]) return false;
  if (mac[3] != ctx.h[3]) return false;

  return true;
}

KERNEL_FQ KERNEL_FA void m39000_mxx (KERN_ATTR_RULES_ESALT (krb5pa_3_t))
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

  COPY_PW (pws[gid]);

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 w[64];

    krb5_des_build_buf (tmp.i, tmp.pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, tmp.pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_pa_timestamp_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp, esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp_len, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m39000_sxx (KERN_ATTR_RULES_ESALT (krb5pa_3_t))
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

  COPY_PW (pws[gid]);

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 w[64];

    krb5_des_build_buf (tmp.i, tmp.pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, tmp.pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_pa_timestamp_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp, esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp_len, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
