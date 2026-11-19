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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct krb5asrep
{
  u32 raw_token[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;

  u32 user[128];
  u32 realm[128];
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

DECLSPEC void rc4_init_128_virtual4 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
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

DECLSPEC int asrep_early_check (LOCAL_AS u32 *S, const u32 edata2_2, const u32 edata2_3, const u64 lid)
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

  if (((((u32) tmp ^ edata2_2) & 0xff) != 0x79) && ((((u32) tmp ^ edata2_2) & 0xff) != 0x7a)) return 0;

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

DECLSPEC int decrypt_and_check_full (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, PRIVATE_AS const u32 *K2, PRIVATE_AS const u32 *checksum, const u64 lid)
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

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, PRIVATE_AS const u32 *K2, PRIVATE_AS const u32 *checksum, const u64 lid)
{
  // the prefetching key schedule costs an AMD GPU, see inc_cipher_rc4.cl

  #if defined IS_AMD_USE_HIP || defined IS_AMD_GPU
  rc4_init_128 (S, data, lid);
  #else
  rc4_init_128_virtual4 (S, data, lid);
  #endif

  if (asrep_early_check (S, edata2[2], edata2[3], lid) == 0) return 0;

  return decrypt_and_check_full (S, data, edata2, edata2_len, K2, checksum, lid);
}

DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *K, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest, PRIVATE_AS u32 *K2)
{
  // Everything from the NT hash on has a fixed size whatever the password is, so each HMAC is two
  // bare transforms for the pads and two for the message.

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 ipad[4];
  u32 opad[4];

  // K1 = HMAC-MD5 (K, 8), the key usage number as four little endian bytes

  w0[0] = K[0];
  w0[1] = K[1];
  w0[2] = K[2];
  w0[3] = K[3];
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

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  w0[0] = 8;
  w0[1] = 0x80;
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
  w3[2] = (64 + 4) * 8;
  w3[3] = 0;

  hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);

  K2[0] = digest[0];
  K2[1] = digest[1];
  K2[2] = digest[2];
  K2[3] = digest[3];

  // K3 = HMAC-MD5 (K1, checksum)

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
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

  hmac_md5_pad (w0, w1, w2, w3, ipad, opad);

  w0[0] = checksum[0];
  w0[1] = checksum[1];
  w0[2] = checksum[2];
  w0[3] = checksum[3];
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

  hmac_md5_run (w0, w1, w2, w3, ipad, opad, digest);
}

// Whether the amplifier word of a candidate leaves it a single MD4 block: up to 27 characters with
// the base word, and plain ASCII. The base word is tested once, by kerb_comb_base ().

DECLSPEC int kerb_comb_single (const u32 pw_l_len, GLOBAL_AS const u32 *r, const u32 pw_r_len)
{
  if ((pw_l_len + pw_r_len) > 27) return 0;

  u32 hi = 0;

  for (u32 i = 0, idx = 0; i < pw_r_len; i += 4, idx += 1)
  {
    const u32 left = pw_r_len - i;

    hi |= (left >= 4) ? r[idx] : (r[idx] & (0xffffffffU >> ((4 - left) * 8)));
  }

  return ((hi & 0x80808080) == 0);
}

// The base word as the first two words of a block, for a base word that may be part of a single
// MD4 block. Returns 0 for one that never is.

DECLSPEC int kerb_comb_base (GLOBAL_AS const u32 *l, const u32 pw_l_len, PRIVATE_AS u32 *l0, PRIVATE_AS u32 *l1)
{
  l0[0] = 0;
  l0[1] = 0;
  l0[2] = 0;
  l0[3] = 0;
  l1[0] = 0;
  l1[1] = 0;
  l1[2] = 0;
  l1[3] = 0;

  if (pw_l_len > 27) return 0;

  u32 t[8] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_l_len; i += 4, idx += 1)
  {
    const u32 left = pw_l_len - i;

    t[idx] = (left >= 4) ? l[idx] : (l[idx] & (0xffffffffU >> ((4 - left) * 8)));
  }

  const u32 hi = t[0] | t[1] | t[2] | t[3] | t[4] | t[5] | t[6];

  if ((hi & 0x80808080) != 0) return 0;

  l0[0] = t[0];
  l0[1] = t[1];
  l0[2] = t[2];
  l0[3] = t[3];
  l1[0] = t[4];
  l1[1] = t[5];
  l1[2] = t[6];

  return 1;
}

// The single MD4 block of a candidate that kerb_comb_single () passed: the two words joined the way
// the optimized kernel joins them, widened to UTF-16 and padded.

DECLSPEC void kerb_comb_block (PRIVATE_AS const u32 *l0, PRIVATE_AS const u32 *l1, const u32 pw_l_len, GLOBAL_AS const u32 *r, const u32 pw_r_len, const u32 base_left, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3)
{
  u32 wordl0[4];
  u32 wordl1[4];
  u32 wordl2[4];
  u32 wordl3[4];

  wordl0[0] = l0[0];
  wordl0[1] = l0[1];
  wordl0[2] = l0[2];
  wordl0[3] = l0[3];
  wordl1[0] = l1[0];
  wordl1[1] = l1[1];
  wordl1[2] = l1[2];
  wordl1[3] = l1[3];
  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;
  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  u32 t[8] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_r_len; i += 4, idx += 1)
  {
    const u32 left = pw_r_len - i;

    t[idx] = (left >= 4) ? r[idx] : (r[idx] & (0xffffffffU >> ((4 - left) * 8)));
  }

  u32 wordr0[4];
  u32 wordr1[4];
  u32 wordr2[4];
  u32 wordr3[4];

  wordr0[0] = t[0];
  wordr0[1] = t[1];
  wordr0[2] = t[2];
  wordr0[3] = t[3];
  wordr1[0] = t[4];
  wordr1[1] = t[5];
  wordr1[2] = t[6];
  wordr1[3] = 0;
  wordr2[0] = 0;
  wordr2[1] = 0;
  wordr2[2] = 0;
  wordr2[3] = 0;
  wordr3[0] = 0;
  wordr3[1] = 0;
  wordr3[2] = 0;
  wordr3[3] = 0;

  if (base_left == 1)
  {
    switch_buffer_by_offset_le_S (wordr0, wordr1, wordr2, wordr3, pw_l_len);
  }
  else
  {
    switch_buffer_by_offset_le_S (wordl0, wordl1, wordl2, wordl3, pw_r_len);
  }

  w0[0] = wordl0[0] | wordr0[0];
  w0[1] = wordl0[1] | wordr0[1];
  w0[2] = wordl0[2] | wordr0[2];
  w0[3] = wordl0[3] | wordr0[3];
  w1[0] = wordl1[0] | wordr1[0];
  w1[1] = wordl1[1] | wordr1[1];
  w1[2] = wordl1[2] | wordr1[2];
  w1[3] = wordl1[3] | wordr1[3];

  const u32 pw_len = pw_l_len + pw_r_len;

  append_0x80_2x4_S (w0, w1, pw_len);

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w3[2] = pw_len * 8 * 2;
  w3[3] = 0;
}

KERNEL_FQ KERNEL_FA void m18200_mxx (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  // A candidate that is a single MD4 block is joined the way the optimized kernel joins it and
  // hashed with a bare transform, in a loop of its own. The streaming path costs speed in the loop it
  // is in even when it is never taken, so it picks up the rest in a second loop: every candidate of
  // a base word that is too long or not plain ASCII, the ones whose amplifier word makes them so,
  // and all of them under a mask that puts the base word in the middle.

  const u32 pw_l_len = pws[gid].pw_len;

  u32 l0[4];
  u32 l1[4];

  const int single = (COMBS_IS_MIDDLE) ? 0 : kerb_comb_base (pws[gid].i, pw_l_len, l0, l1);

  const u32 base_left = (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT) ? 1 : 0;

  int streamed = (single == 0);

  if (single == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
    {
      const u32 pw_r_len = combs_buf[il_pos].pw_len;

      if (kerb_comb_single (pw_l_len, combs_buf[il_pos].i, pw_r_len) == 0)
      {
        streamed = 1;

        continue;
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      kerb_comb_block (l0, l1, pw_l_len, combs_buf[il_pos].i, pw_r_len, base_left, w0, w1, w2, w3);

      u32 K[4];

      K[0] = MD4M_A;
      K[1] = MD4M_B;
      K[2] = MD4M_C;
      K[3] = MD4M_D;

      md4_transform (w0, w1, w2, w3, K);

      u32 digest[4];

      u32 K2[4];

      kerb_prepare (K, checksum, digest, K2);

      if (decrypt_and_check (S, digest, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, K2, checksum, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }

  if (streamed == 0) return;

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
    if ((single == 1) && (kerb_comb_single (pw_l_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len) == 1)) continue;

    md4_ctx_t ctx;

    // -a 1 may choose the larger wordlist as the base word source, which puts the amplifier word in
    // front of the base word (BASE_RIGHT). The context that already absorbed the base word cannot be
    // reused for that, so start from the pre-base context, feed the amplifier, then the base word.

    if (COMBS_MODE == COMBINATOR_MODE_BASE_RIGHT)
    {
      ctx = ctx0_pre;

      md4_update_global_utf16le (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
      md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);
    }
    else
    {
      ctx = ctx0;

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
    }

    md4_final (&ctx);

    u32 digest[4];

    u32 K2[4];

    kerb_prepare (ctx.h, checksum, digest, K2);

    if (decrypt_and_check (S, digest, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, K2, checksum, lid) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m18200_sxx (KERN_ATTR_ESALT (krb5asrep_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  u32 checksum[4];

  checksum[0] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0];
  checksum[1] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1];
  checksum[2] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2];
  checksum[3] = esalt_bufs[DIGESTS_OFFSET_HOST].checksum[3];

  // A candidate that is a single MD4 block is joined the way the optimized kernel joins it and
  // hashed with a bare transform, in a loop of its own. The streaming path costs speed in the loop it
  // is in even when it is never taken, so it picks up the rest in a second loop: every candidate of
  // a base word that is too long or not plain ASCII, the ones whose amplifier word makes them so,
  // and all of them under a mask that puts the base word in the middle.

  const u32 pw_l_len = pws[gid].pw_len;

  u32 l0[4];
  u32 l1[4];

  const int single = (COMBS_IS_MIDDLE) ? 0 : kerb_comb_base (pws[gid].i, pw_l_len, l0, l1);

  const u32 base_left = (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT) ? 1 : 0;

  int streamed = (single == 0);

  if (single == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
    {
      const u32 pw_r_len = combs_buf[il_pos].pw_len;

      if (kerb_comb_single (pw_l_len, combs_buf[il_pos].i, pw_r_len) == 0)
      {
        streamed = 1;

        continue;
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      kerb_comb_block (l0, l1, pw_l_len, combs_buf[il_pos].i, pw_r_len, base_left, w0, w1, w2, w3);

      u32 K[4];

      K[0] = MD4M_A;
      K[1] = MD4M_B;
      K[2] = MD4M_C;
      K[3] = MD4M_D;

      md4_transform (w0, w1, w2, w3, K);

      u32 digest[4];

      u32 K2[4];

      kerb_prepare (K, checksum, digest, K2);

      if (decrypt_and_check (S, digest, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, K2, checksum, lid) == 1)
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }

  if (streamed == 0) return;

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
    if ((single == 1) && (kerb_comb_single (pw_l_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len) == 1)) continue;

    md4_ctx_t ctx;

    // -a 1 may choose the larger wordlist as the base word source, which puts the amplifier word in
    // front of the base word (BASE_RIGHT). The context that already absorbed the base word cannot be
    // reused for that, so start from the pre-base context, feed the amplifier, then the base word.

    if (COMBS_MODE == COMBINATOR_MODE_BASE_RIGHT)
    {
      ctx = ctx0_pre;

      md4_update_global_utf16le (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
      md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);
    }
    else
    {
      ctx = ctx0;

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
    }

    md4_final (&ctx);

    u32 digest[4];

    u32 K2[4];

    kerb_prepare (ctx.h, checksum, digest, K2);

    if (decrypt_and_check (S, digest, esalt_bufs[DIGESTS_OFFSET_HOST].edata2, esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len, K2, checksum, lid) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
