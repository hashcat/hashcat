/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bsdicrypt_tmp
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

KERNEL_FQ KERNEL_FA void m12400_init (KERN_ATTR_TMPS (bsdicrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sDES_BOX_S
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans_opti[0][i];
    s_SPtrans[1][i] = c_SPtrans_opti[1][i];
    s_SPtrans[2][i] = c_SPtrans_opti[2][i];
    s_SPtrans[3][i] = c_SPtrans_opti[3][i];
    s_SPtrans[4][i] = c_SPtrans_opti[4][i];
    s_SPtrans[5][i] = c_SPtrans_opti[5][i];
    s_SPtrans[6][i] = c_SPtrans_opti[6][i];
    s_SPtrans[7][i] = c_SPtrans_opti[7][i];

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

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * word
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32 Kc[16];
  u32 Kd[16];

  u32 out[2];

  out[0] = (w[0] << 1) & 0xfefefefe;
  out[1] = (w[1] << 1) & 0xfefefefe;

  for (u32 i = 8, j = 2; i < pw_len; i += 8, j += 2)
  {
    _des_crypt_keysetup_opti (out[0], out[1], Kc, Kd, s_skb);

    DES_IP_S (out[0], out[1]);

    out[0] = hc_rotr32_S (out[0], 31);
    out[1] = hc_rotr32_S (out[1], 31);

    _des_crypt_encrypt_mask_rounds (out, 0, 1, Kc, Kd, s_SPtrans);

    out[0] = hc_rotl32_S (out[0], 31);
    out[1] = hc_rotl32_S (out[1], 31);

    DES_FP_S (out[1], out[0]);

    const u32 R = (w[j + 0] << 1) & 0xfefefefe;
    const u32 L = (w[j + 1] << 1) & 0xfefefefe;

    out[0] ^= R;
    out[1] ^= L;
  }

  /*
  out[0] = (out[0] & 0xfefefefe) >> 1;
  out[1] = (out[1] & 0xfefefefe) >> 1;

  out[0] = (out[0] << 1) & 0xfefefefe;
  out[1] = (out[1] << 1) & 0xfefefefe;
  */

  _des_crypt_keysetup_opti (out[0], out[1], Kc, Kd, s_skb);

  tmps[gid].Kc[ 0] = Kc[ 0];
  tmps[gid].Kc[ 1] = Kc[ 1];
  tmps[gid].Kc[ 2] = Kc[ 2];
  tmps[gid].Kc[ 3] = Kc[ 3];
  tmps[gid].Kc[ 4] = Kc[ 4];
  tmps[gid].Kc[ 5] = Kc[ 5];
  tmps[gid].Kc[ 6] = Kc[ 6];
  tmps[gid].Kc[ 7] = Kc[ 7];
  tmps[gid].Kc[ 8] = Kc[ 8];
  tmps[gid].Kc[ 9] = Kc[ 9];
  tmps[gid].Kc[10] = Kc[10];
  tmps[gid].Kc[11] = Kc[11];
  tmps[gid].Kc[12] = Kc[12];
  tmps[gid].Kc[13] = Kc[13];
  tmps[gid].Kc[14] = Kc[14];
  tmps[gid].Kc[15] = Kc[15];

  tmps[gid].Kd[ 0] = Kd[ 0];
  tmps[gid].Kd[ 1] = Kd[ 1];
  tmps[gid].Kd[ 2] = Kd[ 2];
  tmps[gid].Kd[ 3] = Kd[ 3];
  tmps[gid].Kd[ 4] = Kd[ 4];
  tmps[gid].Kd[ 5] = Kd[ 5];
  tmps[gid].Kd[ 6] = Kd[ 6];
  tmps[gid].Kd[ 7] = Kd[ 7];
  tmps[gid].Kd[ 8] = Kd[ 8];
  tmps[gid].Kd[ 9] = Kd[ 9];
  tmps[gid].Kd[10] = Kd[10];
  tmps[gid].Kd[11] = Kd[11];
  tmps[gid].Kd[12] = Kd[12];
  tmps[gid].Kd[13] = Kd[13];
  tmps[gid].Kd[14] = Kd[14];
  tmps[gid].Kd[15] = Kd[15];

  tmps[gid].iv[0] = 0;
  tmps[gid].iv[1] = 0;
}

KERNEL_FQ KERNEL_FA void m12400_loop (KERN_ATTR_TMPS (bsdicrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sDES_BOX_S
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans_opti[0][i];
    s_SPtrans[1][i] = c_SPtrans_opti[1][i];
    s_SPtrans[2][i] = c_SPtrans_opti[2][i];
    s_SPtrans[3][i] = c_SPtrans_opti[3][i];
    s_SPtrans[4][i] = c_SPtrans_opti[4][i];
    s_SPtrans[5][i] = c_SPtrans_opti[5][i];
    s_SPtrans[6][i] = c_SPtrans_opti[6][i];
    s_SPtrans[7][i] = c_SPtrans_opti[7][i];

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

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans_opti;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  u32 Kc[16];

  Kc[ 0] = tmps[gid].Kc[ 0];
  Kc[ 1] = tmps[gid].Kc[ 1];
  Kc[ 2] = tmps[gid].Kc[ 2];
  Kc[ 3] = tmps[gid].Kc[ 3];
  Kc[ 4] = tmps[gid].Kc[ 4];
  Kc[ 5] = tmps[gid].Kc[ 5];
  Kc[ 6] = tmps[gid].Kc[ 6];
  Kc[ 7] = tmps[gid].Kc[ 7];
  Kc[ 8] = tmps[gid].Kc[ 8];
  Kc[ 9] = tmps[gid].Kc[ 9];
  Kc[10] = tmps[gid].Kc[10];
  Kc[11] = tmps[gid].Kc[11];
  Kc[12] = tmps[gid].Kc[12];
  Kc[13] = tmps[gid].Kc[13];
  Kc[14] = tmps[gid].Kc[14];
  Kc[15] = tmps[gid].Kc[15];

  u32 Kd[16];

  Kd[ 0] = tmps[gid].Kd[ 0];
  Kd[ 1] = tmps[gid].Kd[ 1];
  Kd[ 2] = tmps[gid].Kd[ 2];
  Kd[ 3] = tmps[gid].Kd[ 3];
  Kd[ 4] = tmps[gid].Kd[ 4];
  Kd[ 5] = tmps[gid].Kd[ 5];
  Kd[ 6] = tmps[gid].Kd[ 6];
  Kd[ 7] = tmps[gid].Kd[ 7];
  Kd[ 8] = tmps[gid].Kd[ 8];
  Kd[ 9] = tmps[gid].Kd[ 9];
  Kd[10] = tmps[gid].Kd[10];
  Kd[11] = tmps[gid].Kd[11];
  Kd[12] = tmps[gid].Kd[12];
  Kd[13] = tmps[gid].Kd[13];
  Kd[14] = tmps[gid].Kd[14];
  Kd[15] = tmps[gid].Kd[15];

  u32 iv[2];

  iv[0] = tmps[gid].iv[0];
  iv[1] = tmps[gid].iv[1];

  const u32 mask = salt_bufs[SALT_POS_HOST].salt_buf[0];

  _des_crypt_encrypt_mask_rounds (iv, mask, LOOP_CNT, Kc, Kd, s_SPtrans);

  tmps[gid].iv[0] = iv[0];
  tmps[gid].iv[1] = iv[1];
}

KERNEL_FQ KERNEL_FA void m12400_comp (KERN_ATTR_TMPS (bsdicrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  const u32 r0 = tmps[gid].iv[0];
  const u32 r1 = tmps[gid].iv[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
