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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

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

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}
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

typedef struct netntlm_tmp
{
  u32 digest_buf[4];

} netntlm_tmp_t;

KERNEL_FQ KERNEL_FA void m27000_init (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];

  if (is_valid_hex_32_incl_uppercase (in[0]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[1]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[2]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[3]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[4]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[5]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[6]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (in[7]) == 0) return;

  u32 out[4];

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

  for (int i = 0, j = 0; i < 16; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].digest_buf[0] = out[ 0];
  tmps[gid].digest_buf[1] = out[ 1];
  tmps[gid].digest_buf[2] = out[ 2];
  tmps[gid].digest_buf[3] = out[ 3];

}

KERNEL_FQ KERNEL_FA void m27000_loop (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
{

}

KERNEL_FQ KERNEL_FA void m27000_comp (KERN_ATTR_TMPS_ESALT (netntlm_tmp_t, netntlm_t))
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

  if (is_valid_hex_32_incl_uppercase (pws[gid].i[0]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[1]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[2]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[3]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[4]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[5]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[6]) == 0) return;
  if (is_valid_hex_32_incl_uppercase (pws[gid].i[7]) == 0) return;


  /**
   * base
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

  const u32 a = tmps[gid].digest_buf[0];
  const u32 b = tmps[gid].digest_buf[1];
  const u32 c = tmps[gid].digest_buf[2];
  const u32 d = tmps[gid].digest_buf[3];

  // I believe this matches the last 2 bytes and throws away.
  // Taken from 5500.
  if ((d >> 16) != s2) return;

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

  /**
   * digest
   */

  const u32 r0 = out1[0];
  const u32 r1 = out1[1];
  const u32 r2 = out2[0];
  const u32 r3 = out2[1];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
