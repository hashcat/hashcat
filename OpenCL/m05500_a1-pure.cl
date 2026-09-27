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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
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

DECLSPEC void transform_netntlmv1_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *out)
{
  u32 t[8];

  t[0] = (w0 >>  0) & 0xff;
  t[1] = (w0 >>  8) & 0xff;
  t[2] = (w0 >> 16) & 0xff;
  t[3] = (w0 >> 24) & 0xff;
  t[4] = (w1 >>  0) & 0xff;
  t[5] = (w1 >>  8) & 0xff;
  t[6] = (w1 >> 16) & 0xff;
  t[7] = (w1 >> 24) & 0xff;

  u32 k[8];

  k[0] =               (t[0] >> 0);
  k[1] = (t[0] << 7) | (t[1] >> 1);
  k[2] = (t[1] << 6) | (t[2] >> 2);
  k[3] = (t[2] << 5) | (t[3] >> 3);
  k[4] = (t[3] << 4) | (t[4] >> 4);
  k[5] = (t[4] << 3) | (t[5] >> 5);
  k[6] = (t[5] << 2) | (t[6] >> 6);
  k[7] = (t[6] << 1);

  out[0] = ((k[0] & 0xff) <<  0)
         | ((k[1] & 0xff) <<  8)
         | ((k[2] & 0xff) << 16)
         | ((k[3] & 0xff) << 24);

  out[1] = ((k[4] & 0xff) <<  0)
         | ((k[5] & 0xff) <<  8)
         | ((k[6] & 0xff) << 16)
         | ((k[7] & 0xff) << 24);
}

KERNEL_FQ KERNEL_FA void m05500_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
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
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

  /**
   * base
   */

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  md4_ctx_t ctx0_pre = ctx0;

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. Any of them may be empty, and the two in the
    // middle are empty unless the mask carries a ?q.
    //
    // Every thread reads the same il_pos, so the branches below are uniform across the warp and the
    // attack modes that do not take them pay nothing but the compare.

    if (COMBS_IS_MIDDLE)
    {
      if (COMBS_PRE (il_pos).pw_len > 0)
      {
        ctx = ctx0_pre;

        md4_update_global_utf16le (&ctx, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    md4_update_global_utf16le (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    md4_final (&ctx);

    const u32 a = ctx.h[0];
    const u32 b = ctx.h[1];
    const u32 c = ctx.h[2];
    const u32 d = ctx.h[3];

    if ((d >> 16) != s2) continue;

    /**
     * DES1
     */

    u32 key[2];

    transform_netntlmv1_key (a, b, key);

    u32 Kc[16];
    u32 Kd[16];

    _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

    u32 data[2];

    data[0] = s0;
    data[1] = s1;

    u32 out1[2];

    _des_crypt_encrypt_lm (out1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

    u32 out2[2];

    _des_crypt_encrypt_lm (out2, data, Kc, Kd, s_SPtrans);

    const u32 r0 = out1[0];
    const u32 r1 = out1[1];
    const u32 r2 = out2[0];
    const u32 r3 = out2[1];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m05500_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
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
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

  /**
   * base
   */

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  md4_ctx_t ctx0_pre = ctx0;

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. Any of them may be empty, and the two in the
    // middle are empty unless the mask carries a ?q.
    //
    // Every thread reads the same il_pos, so the branches below are uniform across the warp and the
    // attack modes that do not take them pay nothing but the compare.

    if (COMBS_IS_MIDDLE)
    {
      if (COMBS_PRE (il_pos).pw_len > 0)
      {
        ctx = ctx0_pre;

        md4_update_global_utf16le (&ctx, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    md4_update_global_utf16le (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    md4_final (&ctx);

    const u32 a = ctx.h[0];
    const u32 b = ctx.h[1];
    const u32 c = ctx.h[2];
    const u32 d = ctx.h[3];

    if ((d >> 16) != s2) continue;

    /**
     * DES1
     */

    u32 key[2];

    transform_netntlmv1_key (a, b, key);

    u32 Kc[16];
    u32 Kd[16];

    _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

    u32 data[2];

    data[0] = s0;
    data[1] = s1;

    u32 out1[2];

    _des_crypt_encrypt_lm (out1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    /*
    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

    u32 out2[2];

    _des_crypt_encrypt_lm (out2, data, Kc, Kd, s_SPtrans);
    */

    const u32 r0 = out1[0];
    const u32 r1 = out1[1];
    const u32 r2 = search[2];
    const u32 r3 = search[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
