/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// the kernel body is scalar, so VECT_SIZE is left at 1 by not defining this
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_encpart_des.cl)
#endif

typedef struct krb5asrep_3
{
  u32 user[32];
  u32 realm[32];
  u32 joined;

  u32 salt_buf[32];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5asrep_3_t;

// The candidate is assembled as bytes rather than in the combinator's four word registers, which
// hold 64 and derive a length masked to six bits, so a candidate of exactly the 64 this mode takes
// would come out as length 0. m37400 assembles the same way for the same reason. Bytes a longer
// candidate left behind do no harm, because krb5_des_build_buf () reads only up to pw_len.
//
// COMBS_MODE reads kernel_param, so the assembly stays inside the kernel functions.

KERNEL_FQ KERNEL_FA void m38600_mxx (KERN_ATTR_ESALT (krb5asrep_3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

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

  /**
   * base
   */

  u32 pw[64] = { 0 };

  PRIVATE_AS u8 *pw_ptr = (PRIVATE_AS u8 *) pw;

  const u32 pw_l_len = pws[gid].pw_len;

  combs_copy_bytes (pw_ptr, 0, pws[gid].i, pw_l_len);

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pw_l_len + combs_len_S (combs_buf, il_pos, COMBS_MODE);

    #if ATTACK_MODE == 12
    if (COMBS_IS_MIDDLE)
    {
      // -a 12 puts the base word inside the amplifier, so all five pieces are copied per item

      u32 comb_len = combs_copy_bytes (pw_ptr, 0, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);

      comb_len = combs_copy_bytes (pw_ptr, comb_len, pws[gid].i,            pw_l_len);
      comb_len = combs_copy_bytes (pw_ptr, comb_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      comb_len = combs_copy_bytes (pw_ptr, comb_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);

      combs_copy_bytes (pw_ptr, comb_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
    }
    else
    #endif
    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      combs_copy_bytes (pw_ptr, pw_l_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }
    else
    {
      const u32 comb_len = combs_copy_bytes (pw_ptr, 0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      combs_copy_bytes (pw_ptr, comb_len, pws[gid].i, pw_l_len);
    }

    u32 w[64];

    krb5_des_build_buf (pw, pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_encpart_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].checksum, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, true, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m38600_sxx (KERN_ATTR_ESALT (krb5asrep_3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

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

  /**
   * base
   */

  u32 pw[64] = { 0 };

  PRIVATE_AS u8 *pw_ptr = (PRIVATE_AS u8 *) pw;

  const u32 pw_l_len = pws[gid].pw_len;

  combs_copy_bytes (pw_ptr, 0, pws[gid].i, pw_l_len);

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 pw_len = pw_l_len + combs_len_S (combs_buf, il_pos, COMBS_MODE);

    #if ATTACK_MODE == 12
    if (COMBS_IS_MIDDLE)
    {
      // -a 12 puts the base word inside the amplifier, so all five pieces are copied per item

      u32 comb_len = combs_copy_bytes (pw_ptr, 0, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);

      comb_len = combs_copy_bytes (pw_ptr, comb_len, pws[gid].i,            pw_l_len);
      comb_len = combs_copy_bytes (pw_ptr, comb_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      comb_len = combs_copy_bytes (pw_ptr, comb_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);

      combs_copy_bytes (pw_ptr, comb_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
    }
    else
    #endif
    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      combs_copy_bytes (pw_ptr, pw_l_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }
    else
    {
      const u32 comb_len = combs_copy_bytes (pw_ptr, 0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      combs_copy_bytes (pw_ptr, comb_len, pws[gid].i, pw_l_len);
    }

    u32 w[64];

    krb5_des_build_buf (pw, pw_len, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_len, w);

    u32 key[2];

    krb5_des_string_to_key (w, pw_len + salt_len, key, s_SPtrans, s_skb);

    if (krb5_des_encpart_check (key, esalt_bufs[DIGESTS_OFFSET_HOST].checksum, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, true, s_SPtrans, s_skb) == true)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
