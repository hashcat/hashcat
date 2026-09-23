/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct racf_kdfaes_tmp
{
  u32  key[16];
  u32  salt_buf[16];
  u32  salt_len;

  u32  out[256]; // change for mem_fact > 10
  u32  out_len;

  pbkdf2_sha256_tmp_t pbkdf2_tmps;
} racf_kdfaes_tmp_t;

typedef struct racf_kdfaes
{
  u32 salt_buf[64];
  u32 mem_fac;
  u32 rep_fac;

} racf_kdfaes_t;

CONSTANT_VK u32a c_ascii_to_ebcdic[256] =
{
  0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
  0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
  0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
  0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xba, 0xe0, 0xbb, 0xb0, 0x6d,
  0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
  0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
  0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xff,
  0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5, 0xbd, 0xb4, 0x9a, 0x8a, 0x5f, 0xca, 0xaf, 0xbc,
  0x90, 0x8f, 0xea, 0xfa, 0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
  0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,
  0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf, 0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xad, 0xae, 0x59,
  0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
  0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb, 0xdc, 0x8d, 0x8e, 0xdf,
};

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ KERNEL_FA void m63400_init (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 pw_ebcdic[32] = { 0 };

  for (u32 i = 0; i < (pw_len + 3) / 4; i++)
  {
    u32 w = pws[gid].i[i];

    pw_ebcdic[i] = (c_ascii_to_ebcdic[(w >>  0) & 0xff] <<  0)
                 | (c_ascii_to_ebcdic[(w >>  8) & 0xff] <<  8)
                 | (c_ascii_to_ebcdic[(w >> 16) & 0xff] << 16)
                 | (c_ascii_to_ebcdic[(w >> 24) & 0xff] << 24);
  }

  sha256_ctx_t ctx;

  sha256_init (&ctx);
  sha256_update_swap (&ctx, pw_ebcdic, pw_len);
  sha256_final (&ctx);

  u32 hmac_key[16];

  hmac_key[ 0] = ctx.h[0];
  hmac_key[ 1] = ctx.h[1];
  hmac_key[ 2] = ctx.h[2];
  hmac_key[ 3] = ctx.h[3];
  hmac_key[ 4] = ctx.h[4];
  hmac_key[ 5] = ctx.h[5];
  hmac_key[ 6] = ctx.h[6];
  hmac_key[ 7] = ctx.h[7];
  hmac_key[ 8] = 0;
  hmac_key[ 9] = pw_len * 8;
  hmac_key[10] = 0;
  hmac_key[11] = 0;
  hmac_key[12] = 0;
  hmac_key[13] = 0;
  hmac_key[14] = 0;
  hmac_key[15] = 0;

  tmps[gid].key[0] = hmac_key[0];
  tmps[gid].key[1] = hmac_key[1];
  tmps[gid].key[2] = hmac_key[2];
  tmps[gid].key[3] = hmac_key[3];
  tmps[gid].key[4] = hmac_key[4];
  tmps[gid].key[5] = hmac_key[5];
  tmps[gid].key[6] = hmac_key[6];
  tmps[gid].key[7] = hmac_key[7];

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init (&sha256_hmac_ctx, hmac_key, 40);

  tmps[gid].pbkdf2_tmps.ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].pbkdf2_tmps.ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].pbkdf2_tmps.ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].pbkdf2_tmps.ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].pbkdf2_tmps.ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].pbkdf2_tmps.ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].pbkdf2_tmps.ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].pbkdf2_tmps.ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].pbkdf2_tmps.opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].pbkdf2_tmps.opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].pbkdf2_tmps.opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].pbkdf2_tmps.opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].pbkdf2_tmps.opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].pbkdf2_tmps.opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].pbkdf2_tmps.opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].pbkdf2_tmps.opad[7] = sha256_hmac_ctx.opad.h[7];

  u32 salt_buf[16] = { 0 };

  salt_buf[ 0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0]);
  salt_buf[ 1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1]);
  salt_buf[ 2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2]);
  salt_buf[ 3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3]);
  salt_buf[ 4] = esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac;
  salt_buf[ 5] = 0;
  salt_buf[ 6] = 0;
  salt_buf[ 7] = 0;
  salt_buf[ 8] = 0;
  salt_buf[ 9] = 0;
  salt_buf[10] = 0;
  salt_buf[11] = 0;

  sha256_hmac_update (&sha256_hmac_ctx, salt_buf, 20);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

  sha256_hmac_update_64 (&sha256_hmac_ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&sha256_hmac_ctx);

  tmps[gid].pbkdf2_tmps.dgst[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].pbkdf2_tmps.dgst[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].pbkdf2_tmps.dgst[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].pbkdf2_tmps.dgst[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].pbkdf2_tmps.dgst[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].pbkdf2_tmps.dgst[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].pbkdf2_tmps.dgst[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].pbkdf2_tmps.dgst[7] = sha256_hmac_ctx.opad.h[7];

  tmps[gid].pbkdf2_tmps.out[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].pbkdf2_tmps.out[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].pbkdf2_tmps.out[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].pbkdf2_tmps.out[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].pbkdf2_tmps.out[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].pbkdf2_tmps.out[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].pbkdf2_tmps.out[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].pbkdf2_tmps.out[7] = sha256_hmac_ctx.opad.h[7];

  tmps[gid].salt_buf[ 0] = salt_buf[0];
  tmps[gid].salt_buf[ 1] = salt_buf[1];
  tmps[gid].salt_buf[ 2] = salt_buf[2];
  tmps[gid].salt_buf[ 3] = salt_buf[3];
  tmps[gid].salt_buf[ 4] = salt_buf[4];
  tmps[gid].salt_buf[ 5] = 0;
  tmps[gid].salt_buf[ 6] = 0;
  tmps[gid].salt_buf[ 7] = 0;
  tmps[gid].salt_buf[ 8] = 0;
  tmps[gid].salt_buf[ 9] = 0;
  tmps[gid].salt_buf[10] = 0;
  tmps[gid].salt_buf[11] = 0;
  tmps[gid].salt_len = 20;
  tmps[gid].out_len = 0;
}

KERNEL_FQ KERNEL_FA void m63400_loop (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  const u32 rep_total = esalt_bufs[DIGESTS_OFFSET_HOST].rep_fac * 100;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, pbkdf2_tmps.ipad, gid, 0);
  ipad[1] = packv (tmps, pbkdf2_tmps.ipad, gid, 1);
  ipad[2] = packv (tmps, pbkdf2_tmps.ipad, gid, 2);
  ipad[3] = packv (tmps, pbkdf2_tmps.ipad, gid, 3);
  ipad[4] = packv (tmps, pbkdf2_tmps.ipad, gid, 4);
  ipad[5] = packv (tmps, pbkdf2_tmps.ipad, gid, 5);
  ipad[6] = packv (tmps, pbkdf2_tmps.ipad, gid, 6);
  ipad[7] = packv (tmps, pbkdf2_tmps.ipad, gid, 7);

  opad[0] = packv (tmps, pbkdf2_tmps.opad, gid, 0);
  opad[1] = packv (tmps, pbkdf2_tmps.opad, gid, 1);
  opad[2] = packv (tmps, pbkdf2_tmps.opad, gid, 2);
  opad[3] = packv (tmps, pbkdf2_tmps.opad, gid, 3);
  opad[4] = packv (tmps, pbkdf2_tmps.opad, gid, 4);
  opad[5] = packv (tmps, pbkdf2_tmps.opad, gid, 5);
  opad[6] = packv (tmps, pbkdf2_tmps.opad, gid, 6);
  opad[7] = packv (tmps, pbkdf2_tmps.opad, gid, 7);

  u32x dgst[8];
  u32x out_acc[8];

  dgst[0] = packv (tmps, pbkdf2_tmps.dgst, gid, 0);
  dgst[1] = packv (tmps, pbkdf2_tmps.dgst, gid, 1);
  dgst[2] = packv (tmps, pbkdf2_tmps.dgst, gid, 2);
  dgst[3] = packv (tmps, pbkdf2_tmps.dgst, gid, 3);
  dgst[4] = packv (tmps, pbkdf2_tmps.dgst, gid, 4);
  dgst[5] = packv (tmps, pbkdf2_tmps.dgst, gid, 5);
  dgst[6] = packv (tmps, pbkdf2_tmps.dgst, gid, 6);
  dgst[7] = packv (tmps, pbkdf2_tmps.dgst, gid, 7);

  out_acc[0] = packv (tmps, pbkdf2_tmps.out, gid, 0);
  out_acc[1] = packv (tmps, pbkdf2_tmps.out, gid, 1);
  out_acc[2] = packv (tmps, pbkdf2_tmps.out, gid, 2);
  out_acc[3] = packv (tmps, pbkdf2_tmps.out, gid, 3);
  out_acc[4] = packv (tmps, pbkdf2_tmps.out, gid, 4);
  out_acc[5] = packv (tmps, pbkdf2_tmps.out, gid, 5);
  out_acc[6] = packv (tmps, pbkdf2_tmps.out, gid, 6);
  out_acc[7] = packv (tmps, pbkdf2_tmps.out, gid, 7);

  u32x salt[12];

  salt[ 0] = packv (tmps, salt_buf, gid,  0);
  salt[ 1] = packv (tmps, salt_buf, gid,  1);
  salt[ 2] = packv (tmps, salt_buf, gid,  2);
  salt[ 3] = packv (tmps, salt_buf, gid,  3);
  salt[ 4] = packv (tmps, salt_buf, gid,  4);
  salt[ 5] = packv (tmps, salt_buf, gid,  5);
  salt[ 6] = packv (tmps, salt_buf, gid,  6);
  salt[ 7] = packv (tmps, salt_buf, gid,  7);
  salt[ 8] = packv (tmps, salt_buf, gid,  8);
  salt[ 9] = packv (tmps, salt_buf, gid,  9);
  salt[10] = packv (tmps, salt_buf, gid, 10);
  salt[11] = packv (tmps, salt_buf, gid, 11);

  u32 adjusted_start = LOOP_POS + 1;
  u32 block_idx      = adjusted_start / rep_total;
  u32 iter_in_block  = adjusted_start % rep_total;

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    if (iter_in_block == 0)
    {

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = salt[ 0];
      w0[1] = salt[ 1];
      w0[2] = salt[ 2];
      w0[3] = salt[ 3];
      w1[0] = salt[ 4];
      w1[1] = salt[ 5];
      w1[2] = salt[ 6];
      w1[3] = salt[ 7];
      w2[0] = salt[ 8];
      w2[1] = salt[ 9];
      w2[2] = salt[10];
      w2[3] = salt[11];
      w3[0] = 0x00000001;
      w3[1] = 0x80000000;
      w3[2] = 0;
      w3[3] = (64 + 52) * 8;

      dgst[0] = ipad[0];
      dgst[1] = ipad[1];
      dgst[2] = ipad[2];
      dgst[3] = ipad[3];
      dgst[4] = ipad[4];
      dgst[5] = ipad[5];
      dgst[6] = ipad[6];
      dgst[7] = ipad[7];

      sha256_transform_vector (w0, w1, w2, w3, dgst);

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      dgst[0] = opad[0];
      dgst[1] = opad[1];
      dgst[2] = opad[2];
      dgst[3] = opad[3];
      dgst[4] = opad[4];
      dgst[5] = opad[5];
      dgst[6] = opad[6];
      dgst[7] = opad[7];

      sha256_transform_vector (w0, w1, w2, w3, dgst);

      out_acc[0] = dgst[0];
      out_acc[1] = dgst[1];
      out_acc[2] = dgst[2];
      out_acc[3] = dgst[3];
      out_acc[4] = dgst[4];
      out_acc[5] = dgst[5];
      out_acc[6] = dgst[6];
      out_acc[7] = dgst[7];
    }
    else
    {

      u32x last_dgst0 = 0, last_dgst1 = 0, last_dgst2 = 0, last_dgst3 = 0;

      if (iter_in_block == rep_total - 1)
      {
        last_dgst0 = dgst[0];
        last_dgst1 = dgst[1];
        last_dgst2 = dgst[2];
        last_dgst3 = dgst[3];
      }

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out_acc[0] ^= dgst[0];
      out_acc[1] ^= dgst[1];
      out_acc[2] ^= dgst[2];
      out_acc[3] ^= dgst[3];
      out_acc[4] ^= dgst[4];
      out_acc[5] ^= dgst[5];
      out_acc[6] ^= dgst[6];
      out_acc[7] ^= dgst[7];

      if (iter_in_block == rep_total - 1)
      {
        unpackv (tmps, out, gid, block_idx * 8 + 0, out_acc[0]);
        unpackv (tmps, out, gid, block_idx * 8 + 1, out_acc[1]);
        unpackv (tmps, out, gid, block_idx * 8 + 2, out_acc[2]);
        unpackv (tmps, out, gid, block_idx * 8 + 3, out_acc[3]);
        unpackv (tmps, out, gid, block_idx * 8 + 4, out_acc[4]);
        unpackv (tmps, out, gid, block_idx * 8 + 5, out_acc[5]);
        unpackv (tmps, out, gid, block_idx * 8 + 6, out_acc[6]);
        unpackv (tmps, out, gid, block_idx * 8 + 7, out_acc[7]);

        salt[ 0] = last_dgst0;
        salt[ 1] = last_dgst1;
        salt[ 2] = last_dgst2;
        salt[ 3] = last_dgst3;
        salt[ 4] = out_acc[0];
        salt[ 5] = out_acc[1];
        salt[ 6] = out_acc[2];
        salt[ 7] = out_acc[3];
        salt[ 8] = out_acc[4];
        salt[ 9] = out_acc[5];
        salt[10] = out_acc[6];
        salt[11] = out_acc[7];
      }
    }

    iter_in_block++;

    if (iter_in_block == rep_total)
    {
      iter_in_block = 0;
      block_idx++;
    }
  }

  unpackv (tmps, pbkdf2_tmps.dgst, gid, 0, dgst[0]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 1, dgst[1]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 2, dgst[2]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 3, dgst[3]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 4, dgst[4]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 5, dgst[5]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 6, dgst[6]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 7, dgst[7]);

  unpackv (tmps, pbkdf2_tmps.out, gid, 0, out_acc[0]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 1, out_acc[1]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 2, out_acc[2]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 3, out_acc[3]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 4, out_acc[4]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 5, out_acc[5]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 6, out_acc[6]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 7, out_acc[7]);

  unpackv (tmps, salt_buf, gid,  0, salt[ 0]);
  unpackv (tmps, salt_buf, gid,  1, salt[ 1]);
  unpackv (tmps, salt_buf, gid,  2, salt[ 2]);
  unpackv (tmps, salt_buf, gid,  3, salt[ 3]);
  unpackv (tmps, salt_buf, gid,  4, salt[ 4]);
  unpackv (tmps, salt_buf, gid,  5, salt[ 5]);
  unpackv (tmps, salt_buf, gid,  6, salt[ 6]);
  unpackv (tmps, salt_buf, gid,  7, salt[ 7]);
  unpackv (tmps, salt_buf, gid,  8, salt[ 8]);
  unpackv (tmps, salt_buf, gid,  9, salt[ 9]);
  unpackv (tmps, salt_buf, gid, 10, salt[10]);
  unpackv (tmps, salt_buf, gid, 11, salt[11]);
}

KERNEL_FQ KERNEL_FA void m63400_init2 (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].key[0] = tmps[gid].salt_buf[4];
  tmps[gid].key[1] = tmps[gid].salt_buf[5];
  tmps[gid].key[2] = tmps[gid].salt_buf[6];
  tmps[gid].key[3] = tmps[gid].salt_buf[7];
  tmps[gid].key[4] = tmps[gid].salt_buf[8];
  tmps[gid].key[5] = tmps[gid].salt_buf[9];
  tmps[gid].key[6] = tmps[gid].salt_buf[10];
  tmps[gid].key[7] = tmps[gid].salt_buf[11];

  tmps[gid].salt_buf[8] = 0;
  tmps[gid].salt_buf[9] = 0;
  tmps[gid].salt_buf[10] = 0;
  tmps[gid].salt_buf[11] = 0;

  for (u32 i = 0; i < esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac; i += 1)
  {
    u32 n_key = tmps[gid].key[7] & (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1);

    tmps[gid].salt_buf[0] = tmps[gid].out[n_key * 8 + 0];
    tmps[gid].salt_buf[1] = tmps[gid].out[n_key * 8 + 1];
    tmps[gid].salt_buf[2] = tmps[gid].out[n_key * 8 + 2];
    tmps[gid].salt_buf[3] = tmps[gid].out[n_key * 8 + 3];
    tmps[gid].salt_buf[4] = tmps[gid].out[n_key * 8 + 4];
    tmps[gid].salt_buf[5] = tmps[gid].out[n_key * 8 + 5];
    tmps[gid].salt_buf[6] = tmps[gid].out[n_key * 8 + 6];
    tmps[gid].salt_buf[7] = tmps[gid].out[n_key * 8 + 7];

    sha256_hmac_ctx_t sha256_hmac_ctx;

    sha256_hmac_init_global (&sha256_hmac_ctx, tmps[gid].key, 32);

    sha256_hmac_update_global (&sha256_hmac_ctx, tmps[gid].salt_buf, 32);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha256_hmac_update_64 (&sha256_hmac_ctx, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx);

    tmps[gid].out[i * 8 + 0] = sha256_hmac_ctx.opad.h[0];
    tmps[gid].out[i * 8 + 1] = sha256_hmac_ctx.opad.h[1];
    tmps[gid].out[i * 8 + 2] = sha256_hmac_ctx.opad.h[2];
    tmps[gid].out[i * 8 + 3] = sha256_hmac_ctx.opad.h[3];
    tmps[gid].out[i * 8 + 4] = sha256_hmac_ctx.opad.h[4];
    tmps[gid].out[i * 8 + 5] = sha256_hmac_ctx.opad.h[5];
    tmps[gid].out[i * 8 + 6] = sha256_hmac_ctx.opad.h[6];
    tmps[gid].out[i * 8 + 7] = sha256_hmac_ctx.opad.h[7];

    tmps[gid].key[0] = sha256_hmac_ctx.opad.h[0];
    tmps[gid].key[1] = sha256_hmac_ctx.opad.h[1];
    tmps[gid].key[2] = sha256_hmac_ctx.opad.h[2];
    tmps[gid].key[3] = sha256_hmac_ctx.opad.h[3];
    tmps[gid].key[4] = sha256_hmac_ctx.opad.h[4];
    tmps[gid].key[5] = sha256_hmac_ctx.opad.h[5];
    tmps[gid].key[6] = sha256_hmac_ctx.opad.h[6];
    tmps[gid].key[7] = sha256_hmac_ctx.opad.h[7];
  }

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global (&sha256_hmac_ctx, tmps[gid].key, 32);

  tmps[gid].pbkdf2_tmps.ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].pbkdf2_tmps.ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].pbkdf2_tmps.ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].pbkdf2_tmps.ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].pbkdf2_tmps.ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].pbkdf2_tmps.ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].pbkdf2_tmps.ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].pbkdf2_tmps.ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].pbkdf2_tmps.opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].pbkdf2_tmps.opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].pbkdf2_tmps.opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].pbkdf2_tmps.opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].pbkdf2_tmps.opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].pbkdf2_tmps.opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].pbkdf2_tmps.opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].pbkdf2_tmps.opad[7] = sha256_hmac_ctx.opad.h[7];

  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 0] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 1] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 2] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 3] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 4] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 5] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 6] = 0;
  tmps[gid].out[8 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1) + 7] = 0;

  sha256_hmac_update_global (&sha256_hmac_ctx, tmps[gid].out, 32 * (esalt_bufs[DIGESTS_OFFSET_HOST].mem_fac - 1));

  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    tmps[gid].pbkdf2_tmps.dgst[0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].pbkdf2_tmps.dgst[1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].pbkdf2_tmps.dgst[2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].pbkdf2_tmps.dgst[3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].pbkdf2_tmps.dgst[4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].pbkdf2_tmps.dgst[5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].pbkdf2_tmps.dgst[6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].pbkdf2_tmps.dgst[7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].pbkdf2_tmps.out[0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].pbkdf2_tmps.out[1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].pbkdf2_tmps.out[2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].pbkdf2_tmps.out[3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].pbkdf2_tmps.out[4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].pbkdf2_tmps.out[5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].pbkdf2_tmps.out[6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].pbkdf2_tmps.out[7] = sha256_hmac_ctx2.opad.h[7];
  }
}

KERNEL_FQ KERNEL_FA void m63400_loop2 (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, pbkdf2_tmps.ipad, gid, 0);
  ipad[1] = packv (tmps, pbkdf2_tmps.ipad, gid, 1);
  ipad[2] = packv (tmps, pbkdf2_tmps.ipad, gid, 2);
  ipad[3] = packv (tmps, pbkdf2_tmps.ipad, gid, 3);
  ipad[4] = packv (tmps, pbkdf2_tmps.ipad, gid, 4);
  ipad[5] = packv (tmps, pbkdf2_tmps.ipad, gid, 5);
  ipad[6] = packv (tmps, pbkdf2_tmps.ipad, gid, 6);
  ipad[7] = packv (tmps, pbkdf2_tmps.ipad, gid, 7);

  opad[0] = packv (tmps, pbkdf2_tmps.opad, gid, 0);
  opad[1] = packv (tmps, pbkdf2_tmps.opad, gid, 1);
  opad[2] = packv (tmps, pbkdf2_tmps.opad, gid, 2);
  opad[3] = packv (tmps, pbkdf2_tmps.opad, gid, 3);
  opad[4] = packv (tmps, pbkdf2_tmps.opad, gid, 4);
  opad[5] = packv (tmps, pbkdf2_tmps.opad, gid, 5);
  opad[6] = packv (tmps, pbkdf2_tmps.opad, gid, 6);
  opad[7] = packv (tmps, pbkdf2_tmps.opad, gid, 7);

  u32x dgst[8];
  u32x out[8];

  dgst[0] = packv (tmps, pbkdf2_tmps.dgst, gid, 0);
  dgst[1] = packv (tmps, pbkdf2_tmps.dgst, gid, 1);
  dgst[2] = packv (tmps, pbkdf2_tmps.dgst, gid, 2);
  dgst[3] = packv (tmps, pbkdf2_tmps.dgst, gid, 3);
  dgst[4] = packv (tmps, pbkdf2_tmps.dgst, gid, 4);
  dgst[5] = packv (tmps, pbkdf2_tmps.dgst, gid, 5);
  dgst[6] = packv (tmps, pbkdf2_tmps.dgst, gid, 6);
  dgst[7] = packv (tmps, pbkdf2_tmps.dgst, gid, 7);

  out[0] = packv (tmps, pbkdf2_tmps.out, gid, 0);
  out[1] = packv (tmps, pbkdf2_tmps.out, gid, 1);
  out[2] = packv (tmps, pbkdf2_tmps.out, gid, 2);
  out[3] = packv (tmps, pbkdf2_tmps.out, gid, 3);
  out[4] = packv (tmps, pbkdf2_tmps.out, gid, 4);
  out[5] = packv (tmps, pbkdf2_tmps.out, gid, 5);
  out[6] = packv (tmps, pbkdf2_tmps.out, gid, 6);
  out[7] = packv (tmps, pbkdf2_tmps.out, gid, 7);

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = dgst[5];
    w1[2] = dgst[6];
    w1[3] = dgst[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 32) * 8;

    hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  unpackv (tmps, pbkdf2_tmps.dgst, gid, 0, dgst[0]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 1, dgst[1]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 2, dgst[2]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 3, dgst[3]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 4, dgst[4]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 5, dgst[5]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 6, dgst[6]);
  unpackv (tmps, pbkdf2_tmps.dgst, gid, 7, dgst[7]);

  unpackv (tmps, pbkdf2_tmps.out, gid, 0, out[0]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 1, out[1]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 2, out[2]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 3, out[3]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 4, out[4]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 5, out[5]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 6, out[6]);
  unpackv (tmps, pbkdf2_tmps.out, gid, 7, out[7]);
}

KERNEL_FQ KERNEL_FA void m63400_comp (KERN_ATTR_TMPS_ESALT (racf_kdfaes_tmp_t, racf_kdfaes_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * AES shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  u32 aes_key[8] = {0};

  aes_key[0] = tmps[gid].pbkdf2_tmps.out[0];
  aes_key[1] = tmps[gid].pbkdf2_tmps.out[1];
  aes_key[2] = tmps[gid].pbkdf2_tmps.out[2];
  aes_key[3] = tmps[gid].pbkdf2_tmps.out[3];
  aes_key[4] = tmps[gid].pbkdf2_tmps.out[4];
  aes_key[5] = tmps[gid].pbkdf2_tmps.out[5];
  aes_key[6] = tmps[gid].pbkdf2_tmps.out[6];
  aes_key[7] = tmps[gid].pbkdf2_tmps.out[7];

  u32 plain_text[4] = {0};
  plain_text[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  plain_text[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  plain_text[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  plain_text[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];

  u32 cipher_text[4] = {0};

  u32 aes_ks[60];

  AES256_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);
  aes256_encrypt (aes_ks, plain_text, cipher_text, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = cipher_text[DGST_R0];
  const u32 r1 = cipher_text[DGST_R1];
  const u32 r2 = cipher_text[DGST_R2];
  const u32 r3 = cipher_text[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
