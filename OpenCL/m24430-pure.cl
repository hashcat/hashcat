/**
 * Author......: kozmer
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pkcs12_tmp
{
  u32  dgst[5];
  u32  out[5];

} pkcs12_tmp_t;

typedef struct pkcs12
{
  u32 data_buf[16384];
  int data_len;

  u32 mac_digest[5];

} pkcs12_t;

KERNEL_FQ KERNEL_FA void m24430_init (KERN_ATTR_TMPS_ESALT (pkcs12_tmp_t, pkcs12_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // PKCS#12 KDF (RFC 7292 Appendix B), id=3 for MAC key derivation
  // Compute SHA-1(D || S || P) where:
  //   D = 64 bytes of 0x03
  //   S = salt repeated to 64 bytes
  //   P = UTF-16BE password (with null terminator) repeated to ceil(len/64)*64

  const int pw_len = pws[gid].pw_len;
  const int salt_len = salt_bufs[SALT_POS_HOST].salt_len;
  const int utf16_len = (pw_len + 1) * 2;
  const int v2 = ((utf16_len + 63) / 64) * 64;

  sha1_ctx_t ctx;

  sha1_init (&ctx);

  // diversifier

  {
    u32 w0[4] = { 0x03030303, 0x03030303, 0x03030303, 0x03030303 };
    u32 w1[4] = { 0x03030303, 0x03030303, 0x03030303, 0x03030303 };
    u32 w2[4] = { 0x03030303, 0x03030303, 0x03030303, 0x03030303 };
    u32 w3[4] = { 0x03030303, 0x03030303, 0x03030303, 0x03030303 };

    sha1_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  // salt block

  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    #define SALT_BYTE(k) ((salt_bufs[SALT_POS_HOST].salt_buf[((k) % salt_len) / 4] >> ((((k) % salt_len) & 3) * 8)) & 0xff)
    #define SALT_BE(base) (u32)((SALT_BYTE(base) << 24) | (SALT_BYTE((base)+1) << 16) | (SALT_BYTE((base)+2) << 8) | SALT_BYTE((base)+3))

    w0[0] = SALT_BE ( 0);
    w0[1] = SALT_BE ( 4);
    w0[2] = SALT_BE ( 8);
    w0[3] = SALT_BE (12);
    w1[0] = SALT_BE (16);
    w1[1] = SALT_BE (20);
    w1[2] = SALT_BE (24);
    w1[3] = SALT_BE (28);
    w2[0] = SALT_BE (32);
    w2[1] = SALT_BE (36);
    w2[2] = SALT_BE (40);
    w2[3] = SALT_BE (44);
    w3[0] = SALT_BE (48);
    w3[1] = SALT_BE (52);
    w3[2] = SALT_BE (56);
    w3[3] = SALT_BE (60);

    #undef SALT_BYTE
    #undef SALT_BE

    sha1_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  // password block

  {
    #define PWD_BYTE_RAW(k) (((k) & 1) == 0 ? (u32)0 : ((k) / 2 < pw_len ? ((pws[gid].i[((k) / 2) / 4] >> ((((k) / 2) & 3) * 8)) & 0xff) : (u32)0))
    #define PWD_BYTE(k) PWD_BYTE_RAW((k) % utf16_len)
    #define PWD_BE(base) (u32)((PWD_BYTE(base) << 24) | (PWD_BYTE((base)+1) << 16) | (PWD_BYTE((base)+2) << 8) | PWD_BYTE((base)+3))

    for (int off = 0; off < v2; off += 64)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = PWD_BE (off +  0);
      w0[1] = PWD_BE (off +  4);
      w0[2] = PWD_BE (off +  8);
      w0[3] = PWD_BE (off + 12);
      w1[0] = PWD_BE (off + 16);
      w1[1] = PWD_BE (off + 20);
      w1[2] = PWD_BE (off + 24);
      w1[3] = PWD_BE (off + 28);
      w2[0] = PWD_BE (off + 32);
      w2[1] = PWD_BE (off + 36);
      w2[2] = PWD_BE (off + 40);
      w2[3] = PWD_BE (off + 44);
      w3[0] = PWD_BE (off + 48);
      w3[1] = PWD_BE (off + 52);
      w3[2] = PWD_BE (off + 56);
      w3[3] = PWD_BE (off + 60);

      sha1_update_64 (&ctx, w0, w1, w2, w3, 64);
    }

    #undef PWD_BYTE_RAW
    #undef PWD_BYTE
    #undef PWD_BE
  }

  sha1_final (&ctx);

  tmps[gid].dgst[0] = ctx.h[0];
  tmps[gid].dgst[1] = ctx.h[1];
  tmps[gid].dgst[2] = ctx.h[2];
  tmps[gid].dgst[3] = ctx.h[3];
  tmps[gid].dgst[4] = ctx.h[4];

  tmps[gid].out[0] = ctx.h[0];
  tmps[gid].out[1] = ctx.h[1];
  tmps[gid].out[2] = ctx.h[2];
  tmps[gid].out[3] = ctx.h[3];
  tmps[gid].out[4] = ctx.h[4];
}

KERNEL_FQ KERNEL_FA void m24430_loop (KERN_ATTR_TMPS_ESALT (pkcs12_tmp_t, pkcs12_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[0];
  dgst[1] = tmps[gid].dgst[1];
  dgst[2] = tmps[gid].dgst[2];
  dgst[3] = tmps[gid].dgst[3];
  dgst[4] = tmps[gid].dgst[4];

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = 0x80000000;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 20 * 8;

    dgst[0] = SHA1M_A;
    dgst[1] = SHA1M_B;
    dgst[2] = SHA1M_C;
    dgst[3] = SHA1M_D;
    dgst[4] = SHA1M_E;

    sha1_transform (w0, w1, w2, w3, dgst);
  }

  tmps[gid].dgst[0] = dgst[0];
  tmps[gid].dgst[1] = dgst[1];
  tmps[gid].dgst[2] = dgst[2];
  tmps[gid].dgst[3] = dgst[3];
  tmps[gid].dgst[4] = dgst[4];

  tmps[gid].out[0] = dgst[0];
  tmps[gid].out[1] = dgst[1];
  tmps[gid].out[2] = dgst[2];
  tmps[gid].out[3] = dgst[3];
  tmps[gid].out[4] = dgst[4];
}

KERNEL_FQ KERNEL_FA void m24430_comp (KERN_ATTR_TMPS_ESALT (pkcs12_tmp_t, pkcs12_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // MAC key from KDF

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = tmps[gid].out[0];
  w0[1] = tmps[gid].out[1];
  w0[2] = tmps[gid].out[2];
  w0[3] = tmps[gid].out[3];
  w1[0] = tmps[gid].out[4];
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

  // HMAC-SHA1 over authSafe content

  sha1_hmac_ctx_t hmac_ctx;

  sha1_hmac_init_64 (&hmac_ctx, w0, w1, w2, w3);

  sha1_hmac_update_global_swap (&hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].data_len);

  sha1_hmac_final (&hmac_ctx);

  const u32 r0 = hmac_ctx.opad.h[DGST_R0];
  const u32 r1 = hmac_ctx.opad.h[DGST_R1];
  const u32 r2 = hmac_ctx.opad.h[DGST_R2];
  const u32 r3 = hmac_ctx.opad.h[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
