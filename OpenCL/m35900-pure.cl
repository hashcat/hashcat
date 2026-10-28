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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#define RC4_FOLD_ON_POCL
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#undef RC4_FOLD_ON_POCL
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#ifndef FIXED_LOCAL_SIZE
#define FIXED_LOCAL_SIZE 32
#endif

typedef struct krb5pa
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

typedef struct pa_tmp
{
  u32 nt[4];
} pa_tmp_t;

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert_35500 (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8_35500 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;
  v |= ((u8) hex_convert_35500 (hex[1]) << 0);
  v |= ((u8) hex_convert_35500 (hex[0]) << 4);
  return v;
}
#endif

KERNEL_FQ KERNEL_FA void m35900_init (KERN_ATTR_TMPS_ESALT (pa_tmp_t, krb5pa_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 in[8];
  in[0] = pws[gid].i[0];
  in[1] = pws[gid].i[1];
  in[2] = pws[gid].i[2];
  in[3] = pws[gid].i[3];
  in[4] = pws[gid].i[4];
  in[5] = pws[gid].i[5];
  in[6] = pws[gid].i[6];
  in[7] = pws[gid].i[7];

  u8 nt16[16];
  PRIVATE_AS u8 *in_ptr = (PRIVATE_AS u8 *) in;

  for (int i = 0, j = 0; i < 16; i++, j += 2)
  {
    nt16[i] = hex_to_u8_35500 (in_ptr + j);
  }

  tmps[gid].nt[0] = (u32) nt16[ 0]       | ((u32) nt16[ 1] <<  8) | ((u32) nt16[ 2] << 16) | ((u32) nt16[ 3] << 24);
  tmps[gid].nt[1] = (u32) nt16[ 4]       | ((u32) nt16[ 5] <<  8) | ((u32) nt16[ 6] << 16) | ((u32) nt16[ 7] << 24);
  tmps[gid].nt[2] = (u32) nt16[ 8]       | ((u32) nt16[ 9] <<  8) | ((u32) nt16[10] << 16) | ((u32) nt16[11] << 24);
  tmps[gid].nt[3] = (u32) nt16[12]       | ((u32) nt16[13] <<  8) | ((u32) nt16[14] << 16) | ((u32) nt16[15] << 24);
}

KERNEL_FQ KERNEL_FA void m35900_loop (KERN_ATTR_TMPS_ESALT (pa_tmp_t, krb5pa_t))
{

}

KERNEL_FQ KERNEL_FA void m35900_comp (KERN_ATTR_TMPS_ESALT (pa_tmp_t, krb5pa_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id  (0);

  if (gid >= GID_CNT) return;

  u32 checksum[4];
  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 K1[4], K3[4];


  {
    md5_hmac_ctx_t ctx1;

    u32 k0[4] = { tmps[gid].nt[0], tmps[gid].nt[1], tmps[gid].nt[2], tmps[gid].nt[3] };
    u32 k1[4] = { 0,0,0,0 };
    u32 k2[4] = { 0,0,0,0 };
    u32 k3[4] = { 0,0,0,0 };

    md5_hmac_init_64 (&ctx1, k0, k1, k2, k3);

    u32 m0[4] = { 1, 0, 0, 0 };
    u32 m1[4] = { 0, 0, 0, 0 };
    u32 m2[4] = { 0, 0, 0, 0 };
    u32 m3[4] = { 0, 0, 0, 0 };

    md5_hmac_update_64 (&ctx1, m0, m1, m2, m3, 4);
    md5_hmac_final (&ctx1);

    K1[0] = ctx1.opad.h[0];
    K1[1] = ctx1.opad.h[1];
    K1[2] = ctx1.opad.h[2];
    K1[3] = ctx1.opad.h[3];

    md5_hmac_ctx_t ctx3;

    u32 wk0[4] = { K1[0], K1[1], K1[2], K1[3] };
    u32 wk1[4] = { 0,0,0,0 };
    u32 wk2[4] = { 0,0,0,0 };
    u32 wk3[4] = { 0,0,0,0 };

    md5_hmac_init_64 (&ctx3, wk0, wk1, wk2, wk3);

    u32 c0[4] = { checksum[0], checksum[1], checksum[2], checksum[3] };
    u32 c1[4] = { 0,0,0,0 };
    u32 c2[4] = { 0,0,0,0 };
    u32 c3[4] = { 0,0,0,0 };

    md5_hmac_update_64 (&ctx3, c0, c1, c2, c3, 16);
    md5_hmac_final (&ctx3);

    K3[0] = ctx3.opad.h[0];
    K3[1] = ctx3.opad.h[1];
    K3[2] = ctx3.opad.h[2];
    K3[3] = ctx3.opad.h[3];
  }


  {
    PRIVATE_AS u32 key0[4] = { K3[0], K3[1], K3[2], K3[3] };
    rc4_init_128 (S, (PRIVATE_AS u32 *) key0, lid);

    u32 out[4];
    u8 i = 0, j = 0;

    j = rc4_next_16_global (S, i, j, esalt_bufs[DIGESTS_OFFSET_HOST].timestamp + 0, out, lid); i += 16;


    if ((out[3] & 0xffff0000) != 0x30320000) return;

    j = rc4_next_16_global (S, i, j, esalt_bufs[DIGESTS_OFFSET_HOST].timestamp + 4, out, lid);

    if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return; out[0] >>= 8;
    if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return; out[0] >>= 8;
    if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return; out[0] >>= 8;
    if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return;
    if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return; out[1] >>= 8;
    if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return; out[1] >>= 8;
    if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return; out[1] >>= 8;
    if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return;
    if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return; out[2] >>= 8;
    if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return; out[2] >>= 8;
    if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return; out[2] >>= 8;
    if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return;
  }

  {
    PRIVATE_AS u32 key0[4] = { K3[0], K3[1], K3[2], K3[3] };
    rc4_init_128 (S, (PRIVATE_AS u32 *) key0, lid);
  }

  md5_hmac_ctx_t hctx;

  {
    u32 hk0[4] = { K1[0], K1[1], K1[2], K1[3] };
    u32 hk1[4] = { 0,0,0,0 };
    u32 hk2[4] = { 0,0,0,0 };
    u32 hk3[4] = { 0,0,0,0 };

    md5_hmac_init_64 (&hctx, hk0, hk1, hk2, hk3);
  }

  u32 i = 0, j = 0;

  PRIVATE_AS u32 w0[4], w1[4], w2[4], w3[4];

  j = rc4_next_16_global (S, i, j, esalt_bufs[DIGESTS_OFFSET_HOST].timestamp +  0, w0, lid); i += 16;
  j = rc4_next_16_global (S, i, j, esalt_bufs[DIGESTS_OFFSET_HOST].timestamp +  4, w1, lid); i += 16;

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  j = rc4_next_16_global (S, i, j, esalt_bufs[DIGESTS_OFFSET_HOST].timestamp +  8, w2, lid); i += 16;
  truncate_block_4x4_le_S (w2, 4);

  md5_hmac_update_64 (&hctx, w0, w1, w2, w3, 36);

  md5_hmac_final (&hctx);

  const u32 r0 = hctx.opad.h[0];
  const u32 r1 = hctx.opad.h[1];
  const u32 r2 = hctx.opad.h[2];
  const u32 r3 = hctx.opad.h[3];



  #define il_pos 0
  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
