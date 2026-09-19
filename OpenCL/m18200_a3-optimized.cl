/**
 * Author......: see docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;

} krb5asrep_t;

DECLSPEC void hmac_md5_pad (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *ipad, PRIVATE_AS u32 *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_md5_run (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *ipad, PRIVATE_AS u32 *opad, PRIVATE_AS u32 *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform (w0, w1, w2, w3, digest);
}

#define M18200_RC4_KSA_PREFETCH_STEP(d)       \
{                                             \
  const u8 s_next = GET_KEY8 (S, idx + 1, lid); \
  j += s_i + (d);                             \
  const u8 s_j = GET_KEY8 (S, j, lid);        \
  SET_KEY8 (S, idx, s_j, lid);                \
  SET_KEY8 (S, j, s_i, lid);                  \
  idx++;                                      \
  s_i = (j == idx) ? s_i : s_next;            \
}

DECLSPEC void rc4_init_128_virtual4 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u32 lid)
{
  u32 v = 0x07060504;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 1; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  v = key[0];

  const u8 d0 = v8a_from_v32_S (v);
  const u8 d1 = v8b_from_v32_S (v);
  const u8 d2 = v8c_from_v32_S (v);
  const u8 d3 = v8d_from_v32_S (v);

  // The first four swaps start from the identity permutation. Track their
  // sparse updates in registers, then commit them in program order.

  const u8 j0 = d0;

  const u8 s1  = (j0 == 1) ? 0 : 1;
  const u8 j1  = j0 + s1 + d1;
  const u8 sj1 = (j1 == j0) ? 0 : ((j1 == 0) ? j0 : j1);

  const u8 s2  = (j1 == 2) ? s1 : ((j0 == 2) ? 0 : 2);
  const u8 j2  = j1 + s2 + d2;
  const u8 sj2 = (j2 == j1) ? s1
               : (j2 == 1)  ? sj1
               : (j2 == j0) ? 0
               : (j2 == 0)  ? j0
               : j2;

  const u8 s3  = (j2 == 3) ? s2
               : (j1 == 3) ? s1
               : (j0 == 3) ? 0
               : 3;
  const u8 j3  = j2 + s3 + d3;
  const u8 sj3 = (j3 == j2) ? s2
               : (j3 == 2)  ? sj2
               : (j3 == j1) ? s1
               : (j3 == 1)  ? sj1
               : (j3 == j0) ? 0
               : (j3 == 0)  ? j0
               : j3;

  SET_KEY8 (S, j0,   0, lid);
  SET_KEY8 (S, j1,  s1, lid);
  SET_KEY8 (S, j2,  s2, lid);
  SET_KEY8 (S, j3,  s3, lid);

  // The ordered j writes above establish every update outside positions 0..3.
  // Commit the final low positions together, replacing four byte stores and
  // making their identity initialization unnecessary.

  const u8 s0 = (j3 == 0) ? s3
              : (j2 == 0) ? s2
              : (j1 == 0) ? s1
              : (j0 == 0) ? 0
              : j0;
  const u8 s1_final = (j3 == 1) ? s3
                    : (j2 == 1) ? s2
                    : sj1;
  const u8 s2_final = (j3 == 2) ? s3 : sj2;

  const u32 sbox03 = ((u32) s0       <<  0)
                   | ((u32) s1_final <<  8)
                   | ((u32) s2_final << 16)
                   | ((u32) sj3      << 24);

  SET_KEY32 (S, 0, sbox03, lid);

  u8 j = j3;

  u8 idx = 4;
  u8 s_i = GET_KEY8 (S, idx, lid);

  v = key[1];

  M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  v = key[2];

  M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  v = key[3];

  M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  for (u32 i = 1; i < 16; i++)
  {
    idx = i * 16;

    v = key[0];

    M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[1];

    M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[2];

    M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[3];

    M18200_RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    M18200_RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));
  }
}

#undef M18200_RC4_KSA_PREFETCH_STEP

DECLSPEC int asrep_early_check (LOCAL_AS u32 *S, const u32 edata2_2, const u32 edata2_3, const u32 lid)
{
  u8 a = 0;
  u8 b = 0;
  u8 tmp;
  u8 s_prefetch = GET_KEY8 (S, 1, lid);

  #define RC4_STEP_DISCARD_PREFETCH()             \
  {                                                \
    a += 1;                                        \
    const u8 next = a + 1;                        \
    const u8 Snext = GET_KEY8 (S, next, lid);     \
    const u8 Sa = s_prefetch;                     \
    b += Sa;                                       \
    const u8 Sb = GET_KEY8 (S, b, lid);           \
    SET_KEY8 (S, a, Sb, lid);                      \
    SET_KEY8 (S, b, Sa, lid);                      \
    s_prefetch = (b == next) ? Sa : Snext;        \
  }

  #define RC4_STEP_BYTE_CARRIED(out)              \
  {                                                \
    a += 1;                                        \
    const u8 Sa = s_prefetch;                     \
    b += Sa;                                       \
    const u8 Sb = GET_KEY8 (S, b, lid);           \
    SET_KEY8 (S, a, Sb, lid);                      \
    SET_KEY8 (S, b, Sa, lid);                      \
    const u8 idx = Sa + Sb;                        \
    out = GET_KEY8 (S, idx, lid);                  \
  }

  #define RC4_STEP_DISCARD()             \
  {                                      \
    a += 1;                              \
    const u8 Sa = GET_KEY8 (S, a, lid);  \
    b += Sa;                             \
    const u8 Sb = GET_KEY8 (S, b, lid);  \
    SET_KEY8 (S, a, Sb, lid);            \
    SET_KEY8 (S, b, Sa, lid);            \
  }

  #define RC4_STEP_BYTE(out)             \
  {                                      \
    a += 1;                              \
    const u8 Sa = GET_KEY8 (S, a, lid);  \
    b += Sa;                             \
    const u8 Sb = GET_KEY8 (S, b, lid);  \
    SET_KEY8 (S, a, Sb, lid);            \
    SET_KEY8 (S, b, Sa, lid);            \
    const u8 idx = Sa + Sb;              \
    out = GET_KEY8 (S, idx, lid);        \
  }

  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();
  RC4_STEP_DISCARD_PREFETCH ();

  RC4_STEP_BYTE_CARRIED (tmp);

  if ((((u32) tmp ^ edata2_2) & 0xff) != 0x79) return 0;

  RC4_STEP_BYTE (tmp);

  const u32 len_tag = ((u32) tmp ^ (edata2_2 >> 8)) & 0xff;

  if ((len_tag & 0x80) == 0)
  {
    RC4_STEP_BYTE (tmp);

    return ((((u32) tmp ^ (edata2_2 >> 16)) & 0xff) == 0x30);
  }

  if (len_tag == 0x81)
  {
    RC4_STEP_DISCARD ();
    RC4_STEP_BYTE (tmp);

    return ((((u32) tmp ^ (edata2_2 >> 24)) & 0xff) == 0x30);
  }

  if (len_tag == 0x82)
  {
    RC4_STEP_DISCARD ();
    RC4_STEP_DISCARD ();
    RC4_STEP_BYTE (tmp);

    return ((((u32) tmp ^ edata2_3) & 0xff) == 0x30);
  }

  #undef RC4_STEP_BYTE
  #undef RC4_STEP_BYTE_CARRIED
  #undef RC4_STEP_DISCARD
  #undef RC4_STEP_DISCARD_PREFETCH

  return 0;
}

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, PRIVATE_AS const u32 *K2, PRIVATE_AS const u32 *checksum, const u32 lid)
{
  rc4_init_128 (S, data, lid);

  u8 i = 0;
  u8 j = 0;

  // init hmac

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = K2[0];
  w0[1] = K2[1];
  w0[2] = K2[2];
  w0[3] = K2[3];
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

  u32 ipad[4];
  u32 opad[4];

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  int edata2_left;

  for (edata2_left = edata2_len; edata2_left >= 64; edata2_left -= 64)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;

    md5_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = 0;
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

  if (edata2_left < 16)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w0, edata2_left & 0xf);

    append_0x80_1x4 (w0, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else if (edata2_left < 32)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w1, edata2_left & 0xf);

    append_0x80_1x4 (w1, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else if (edata2_left < 48)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w2, edata2_left & 0xf);

    append_0x80_1x4 (w2, edata2_left & 0xf);

    w3[2] = (64 + edata2_len) * 8;
    w3[3] = 0;

    md5_transform (w0, w1, w2, w3, ipad);
  }
  else
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w3, edata2_left & 0xf);

    append_0x80_1x4 (w3, edata2_left & 0xf);

    if (edata2_left < 56)
    {
      w3[2] = (64 + edata2_len) * 8;
      w3[3] = 0;

      md5_transform (w0, w1, w2, w3, ipad);
    }
    else
    {
      md5_transform (w0, w1, w2, w3, ipad);

      w0[0] = 0;
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
      w3[2] = (64 + edata2_len) * 8;
      w3[3] = 0;

      md5_transform (w0, w1, w2, w3, ipad);
    }
  }

  w0[0] = ipad[0];
  w0[1] = ipad[1];
  w0[2] = ipad[2];
  w0[3] = ipad[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  md5_transform (w0, w1, w2, w3, opad);

  if (checksum[0] != opad[0]) return 0;
  if (checksum[1] != opad[1]) return 0;
  if (checksum[2] != opad[2]) return 0;
  if (checksum[3] != opad[3]) return 0;

  return 1;
}

DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest, const u32 make_k3)
{
  // K=MD4(Little_indian(UNICODE(pwd))

  digest[0] = MD4M_A;
  digest[1] = MD4M_B;
  digest[2] = MD4M_C;
  digest[3] = MD4M_D;

  md4_transform (w0, w1, w2, w3, digest);

  u32 w0_t[4];
  u32 w1_t[4];
  u32 w2_t[4];
  u32 w3_t[4];

  // K1=MD5_HMAC(K,1); with 2 encoded as little indian on 4 bytes (02000000 in hexa);

  w0_t[0] = digest[0];
  w0_t[1] = digest[1];
  w0_t[2] = digest[2];
  w0_t[3] = digest[3];
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  u32 ipad[4];
  u32 opad[4];

  hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

  w0_t[0] = 8;
  w0_t[1] = 0x80;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = (64 + 4) * 8;
  w3_t[3] = 0;

  hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

  // K2 = K1

  if (make_k3 == 0) return;

  // K3=MD5_HMAC(K1,checksum);

  w0_t[0] = digest[0];
  w0_t[1] = digest[1];
  w0_t[2] = digest[2];
  w0_t[3] = digest[3];
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

  w0_t[0] = checksum[0];
  w0_t[1] = checksum[1];
  w0_t[2] = checksum[2];
  w0_t[3] = checksum[3];
  w1_t[0] = 0x80;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = (64 + 16) * 8;
  w3_t[3] = 0;

  hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);
}

DECLSPEC void m18200 (LOCAL_AS u32 *S, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (krb5asrep_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  const u32 edata2_2 = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[2];
  const u32 edata2_3 = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[3];

  /**
   * loop
   */

  u32 md4_w0[4];

  md4_w0[0] = w0[0];
  md4_w0[1] = w0[1];
  md4_w0[2] = w0[2];
  md4_w0[3] = w0[3];

  u32 md4_w1[4];

  md4_w1[0] = w1[0];
  md4_w1[1] = w1[1];
  md4_w1[2] = w1[2];
  md4_w1[3] = w1[3];

  u32 md4_w2[4] = { 0 };
  u32 md4_w3[4] = { 0 };

  append_0x80_2x4 (md4_w0, md4_w1, pw_len);

  make_utf16le_S (md4_w1, md4_w2, md4_w3);
  make_utf16le_S (md4_w0, md4_w0, md4_w1);

  md4_w3[2] = pw_len * 8 * 2;
  md4_w3[3] = 0;

  const u32 md4_w0l0 = md4_w0[0];
  const u32 md4_w0l1 = md4_w0[1];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 w0r = bfs_buf[il_pos].i;

    u32 modifier[4] = { w0r, 0, 0, 0 };
    u32 modifier_utf16[4];
    u32 modifier_unused[4];

    make_utf16le_S (modifier, modifier_utf16, modifier_unused);

    md4_w0[0] = md4_w0l0 | modifier_utf16[0];
    md4_w0[1] = md4_w0l1 | modifier_utf16[1];

    /**
     * kerberos
     */

    u32 digest[4];

    kerb_prepare (md4_w0, md4_w1, md4_w2, md4_w3, checksum, digest, 1);

    u32 tmp[4];

    tmp[0] = digest[0];
    tmp[1] = digest[1];
    tmp[2] = digest[2];
    tmp[3] = digest[3];

    rc4_init_128_virtual4 (S, tmp, lid);

    if (asrep_early_check (S, edata2_2, edata2_3, lid) == 0) continue;

    u32 K2[4];

    kerb_prepare (md4_w0, md4_w1, md4_w2, md4_w3, checksum, K2, 0);

    if (decrypt_and_check (S, tmp, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, K2, checksum, lid) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m18200_m04 (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * base
   */

  const u32 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m18200 (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m18200_m08 (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * base
   */

  const u32 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m18200 (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m18200_m16 (KERN_ATTR_ESALT (krb5asrep_t))
{
}

KERNEL_FQ KERNEL_FA void m18200_s04 (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * base
   */

  const u32 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m18200 (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m18200_s08 (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * base
   */

  const u32 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  m18200 (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m18200_s16 (KERN_ATTR_ESALT (krb5asrep_t))
{
}
