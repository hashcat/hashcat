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

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;
} krb5asrep_t;

typedef struct asrep_tmp
{
  u32 nt[4];
} asrep_tmp_t;

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert_35400 (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8_35400 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;
  v |= ((u8) hex_convert_35400 (hex[1]) << 0);
  v |= ((u8) hex_convert_35400 (hex[0]) << 4);
  return v;
}
#endif

KERNEL_FQ KERNEL_FA void m35400_init (KERN_ATTR_TMPS_ESALT (asrep_tmp_t, krb5asrep_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 in[8];
  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];

  u8 nt16[16];

  PRIVATE_AS u8 *in_ptr = (PRIVATE_AS u8 *) in;

  for (int i = 0, j = 0; i < 16; i++, j += 2)
  {
    nt16[i] = hex_to_u8_35400 (in_ptr + j);
  }

  tmps[gid].nt[0] = (u32) nt16[ 0]       | ((u32) nt16[ 1] <<  8) | ((u32) nt16[ 2] << 16) | ((u32) nt16[ 3] << 24);
  tmps[gid].nt[1] = (u32) nt16[ 4]       | ((u32) nt16[ 5] <<  8) | ((u32) nt16[ 6] << 16) | ((u32) nt16[ 7] << 24);
  tmps[gid].nt[2] = (u32) nt16[ 8]       | ((u32) nt16[ 9] <<  8) | ((u32) nt16[10] << 16) | ((u32) nt16[11] << 24);
  tmps[gid].nt[3] = (u32) nt16[12]       | ((u32) nt16[13] <<  8) | ((u32) nt16[14] << 16) | ((u32) nt16[15] << 24);
}

KERNEL_FQ KERNEL_FA void m35400_loop (KERN_ATTR_TMPS_ESALT (asrep_tmp_t, krb5asrep_t))
{

}

KERNEL_FQ KERNEL_FA void m35400_comp (KERN_ATTR_TMPS_ESALT (asrep_tmp_t, krb5asrep_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id  (0);

  if (gid >= GID_CNT) return;

  u32 checksum[4];
  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  GLOBAL_AS const u32 *edata2    = esalt_bufs[DIGESTS_OFFSET_HOST].edata2;
  const u32           edata2_len = esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len;

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 K1[4], K3[4];

  {
    md5_hmac_ctx_t ctx1;

    u32 k0[4] = { tmps[gid].nt[0], tmps[gid].nt[1], tmps[gid].nt[2], tmps[gid].nt[3] };
    u32 k1[4] = { 0,0,0,0 };
    u32 k2[4] = { 0,0,0,0 };
    u32 k3[4] = { 0,0,0,0 };

    md5_hmac_init_64 (&ctx1, k0, k1, k2, k3);

    u32 m0[4] = { 8, 0, 0, 0 };
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

  u32 out0[4];

  {
    PRIVATE_AS u32 key0[4] = { K3[0], K3[1], K3[2], K3[3] };
    rc4_init_128 (S, (PRIVATE_AS u32 *) key0, lid);
    rc4_next_16_global (S, 0, 0, edata2 + 0, out0, lid);
  }

  if (((out0[2] & 0x00ff80ff) != 0x00300079) &&
      ((out0[2] & 0xFF00FFFF) != 0x30008179) &&
      ((out0[2] & 0x0000FFFF) != 0x00008279 || (out0[3] & 0x000000FF) != 0x00000030))
  {
    return;
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

  GLOBAL_AS const u32 *ptr = edata2;
  u32 remaining = edata2_len;
  u32 i = 0, j = 0;

  PRIVATE_AS u32 w0[4], w1[4], w2[4], w3[4];

  while (remaining >= 64)
  {
    j = rc4_next_16_global (S, i, j, ptr +  0, w0, lid); i += 16;
    j = rc4_next_16_global (S, i, j, ptr +  4, w1, lid); i += 16;
    j = rc4_next_16_global (S, i, j, ptr +  8, w2, lid); i += 16;
    j = rc4_next_16_global (S, i, j, ptr + 12, w3, lid); i += 16;

    md5_hmac_update_64 (&hctx, w0, w1, w2, w3, 64);

    ptr       += 16;
    remaining -= 64;
  }

  w0[0]=w0[1]=w0[2]=w0[3]=0;
  w1[0]=w1[1]=w1[2]=w1[3]=0;
  w2[0]=w2[1]=w2[2]=w2[3]=0;
  w3[0]=w3[1]=w3[2]=w3[3]=0;

  if (remaining)
  {
    if (remaining < 16)
    {
      j = rc4_next_16_global (S, i, j, ptr, w0, lid); i += 16;
      truncate_block_4x4_le_S (w0, remaining & 0xf);
      md5_hmac_update_64 (&hctx, w0, w1, w2, w3, remaining);
    }
    else if (remaining < 32)
    {
      j = rc4_next_16_global (S, i, j, ptr + 0, w0, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 4, w1, lid); i += 16;
      truncate_block_4x4_le_S (w1, remaining & 0xf);
      md5_hmac_update_64 (&hctx, w0, w1, w2, w3, remaining);
    }
    else if (remaining < 48)
    {
      j = rc4_next_16_global (S, i, j, ptr + 0, w0, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 4, w1, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 8, w2, lid); i += 16;
      truncate_block_4x4_le_S (w2, remaining & 0xf);
      md5_hmac_update_64 (&hctx, w0, w1, w2, w3, remaining);
    }
    else
    {
      j = rc4_next_16_global (S, i, j, ptr + 0,  w0, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 4,  w1, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 8,  w2, lid); i += 16;
      j = rc4_next_16_global (S, i, j, ptr + 12, w3, lid); i += 16;
      truncate_block_4x4_le_S (w3, remaining & 0xf);
      md5_hmac_update_64 (&hctx, w0, w1, w2, w3, remaining);
    }
  }

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


