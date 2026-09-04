/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#define RC4_LID_TYPE u64
#define RC4_USE_BITWISE_ADDRESSING
#define RC4_NEXT_16_PREFETCH
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#undef RC4_NEXT_16_PREFETCH
#undef RC4_USE_BITWISE_ADDRESSING
#undef RC4_LID_TYPE
#endif

// autoresearch: ncu shows m09700_s is latency-bound (SM & mem both ~64%, not saturated)
// with only 16.6% occupancy, register-limited to 8 blocks/SM (~255 regs/thread; block =
// FIXED_LOCAL_SIZE = 32 threads = 1 warp). Raise minBlocksPerMultiprocessor so ptxas trims
// registers to fit 9 blocks/SM (~227 regs), lifting occupancy 16.6% -> 18.75% while allowing
// slightly more register headroom than the 10-block setting.
#if defined IS_CUDA || defined IS_HIP
#undef  KERNEL_FA
#define KERNEL_FA __launch_bounds__ (FIXED_LOCAL_SIZE, 9)
#endif

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

// The first MD5 word is complete after step 61.  Keep the working state so the
// final three steps can be deferred until a candidate survives the two-byte
// RC4 reject.
DECLSPEC void m09700_md5_transform_early (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *state)
{
  u32 a = state[0];
  u32 b = state[1];
  u32 c = state[2];
  u32 d = state[3];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  MD5_STEP_S (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP_S (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP_S (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP_S (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP_S (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP_S (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP_S (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP_S (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP_S (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP_S (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  u32 t;

  MD5_STEP_S (MD5_H1, a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP_S (MD5_H1, a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP_S (MD5_H2, d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP_S (MD5_H1, c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP_S (MD5_H2, b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP_S (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP_S (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP_S (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP_S (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP_S (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);

  state[0] = a;
  state[1] = b;
  state[2] = c;
  state[3] = d;
}

DECLSPEC u32 m09700_rc4_next_16_early (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS u32 *state, const u32 verifier2, PRIVATE_AS u32 *out, const u32 search0, const u64 lid)
{
  u8 a = i;
  u8 b = j;

  u32 xor4 = 0;

  u32 tmp;

  u8 idx;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 = tmp;

  const u32 in0 = state[0] + MD5M_A;

  if (((in0 ^ xor4) & 0xff) != (search0 & 0xff)) return 0;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 8;

  if (((in0 ^ xor4) & 0xffff) != (search0 & 0xffff)) return 0;

  u32 md5_a = state[0];
  u32 md5_b = state[1];
  u32 md5_c = state[2];
  u32 md5_d = state[3];

  MD5_STEP_S (MD5_I, md5_d, md5_a, md5_b, md5_c, 0,         MD5C3d, MD5S31);
  MD5_STEP_S (MD5_I, md5_c, md5_d, md5_a, md5_b, verifier2, MD5C3e, MD5S32);
  MD5_STEP_S (MD5_I, md5_b, md5_c, md5_d, md5_a, 0,         MD5C3f, MD5S33);

  state[0] = md5_a + MD5M_A;
  state[1] = md5_b + MD5M_B;
  state[2] = md5_c + MD5M_C;
  state[3] = md5_d + MD5M_D;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 16;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 24;

  out[0] = state[0] ^ xor4;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int k = 1; k < 4; k++)
  {
    xor4 = 0;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 0;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 8;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 16;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 24;

    out[k] = state[k] ^ xor4;
  }

  return 1;
}

DECLSPEC void m09700m (LOCAL_AS u32 *S, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (oldoffice01_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf_t0[4];

  salt_buf_t0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf_t0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf_t0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf_t0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  u32 salt_buf_t1[5];

  salt_buf_t1[0] = hc_bytealign_S (            0, salt_buf_t0[0], 1);
  salt_buf_t1[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 1);
  salt_buf_t1[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 1);
  salt_buf_t1[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 1);
  salt_buf_t1[4] = hc_bytealign_S (salt_buf_t0[3],             0, 1);

  u32 salt_buf_t2[5];

  salt_buf_t2[0] = hc_bytealign_S (            0, salt_buf_t0[0], 2);
  salt_buf_t2[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 2);
  salt_buf_t2[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 2);
  salt_buf_t2[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 2);
  salt_buf_t2[4] = hc_bytealign_S (salt_buf_t0[3],             0, 2);

  u32 salt_buf_t3[5];

  salt_buf_t3[0] = hc_bytealign_S (            0, salt_buf_t0[0], 3);
  salt_buf_t3[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 3);
  salt_buf_t3[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 3);
  salt_buf_t3[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 3);
  salt_buf_t3[4] = hc_bytealign_S (salt_buf_t0[3],             0, 3);

  /**
   * esalt
   */

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    const u32 w0lr = w0l | w0r;

    /**
     * md5
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = pw_len * 8;
    w3_t[3] = 0;

    u32 digest_t0[4];
    u32 digest_t1[2]; // need only first 5 byte
    u32 digest_t2[2];
    u32 digest_t3[2];

    digest_t0[0] = MD5M_A;
    digest_t0[1] = MD5M_B;
    digest_t0[2] = MD5M_C;
    digest_t0[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest_t0);

    // prepare 16 * 21 buffer stuff

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    // offsets

    digest_t0[0] &= 0xffffffff;
    digest_t0[1] &= 0x000000ff;
    digest_t0[2] &= 0x00000000;
    digest_t0[3] &= 0x00000000;

    digest_t1[0] = hc_bytealign_S (           0, digest_t0[0], 1);
    digest_t1[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 1);

    digest_t2[0] = hc_bytealign_S (           0, digest_t0[0], 2);
    digest_t2[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 2);

    digest_t3[0] = hc_bytealign_S (           0, digest_t0[0], 3);
    digest_t3[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 3);

    // generate the 16 * 21 buffer

    // 0..5
    w0_t[0]  = digest_t0[0];
    w0_t[1]  = digest_t0[1];

    // 5..21
    w0_t[1] |= salt_buf_t1[0];
    w0_t[2]  = salt_buf_t1[1];
    w0_t[3]  = salt_buf_t1[2];
    w1_t[0]  = salt_buf_t1[3];
    w1_t[1]  = salt_buf_t1[4];

    // 21..26
    w1_t[1] |= digest_t1[0];
    w1_t[2]  = digest_t1[1];

    // 26..42
    w1_t[2] |= salt_buf_t2[0];
    w1_t[3]  = salt_buf_t2[1];
    w2_t[0]  = salt_buf_t2[2];
    w2_t[1]  = salt_buf_t2[3];
    w2_t[2]  = salt_buf_t2[4];

    // 42..47
    w2_t[2] |= digest_t2[0];
    w2_t[3]  = digest_t2[1];

    // 47..63
    w2_t[3] |= salt_buf_t3[0];
    w3_t[0]  = salt_buf_t3[1];
    w3_t[1]  = salt_buf_t3[2];
    w3_t[2]  = salt_buf_t3[3];
    w3_t[3]  = salt_buf_t3[4];

    // 63..

    w3_t[3] |= digest_t3[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..4
    w0_t[0]  = digest_t3[1];

    // 4..20
    w0_t[1]  = salt_buf_t0[0];
    w0_t[2]  = salt_buf_t0[1];
    w0_t[3]  = salt_buf_t0[2];
    w1_t[0]  = salt_buf_t0[3];

    // 20..25
    w1_t[1]  = digest_t0[0];
    w1_t[2]  = digest_t0[1];

    // 25..41
    w1_t[2] |= salt_buf_t1[0];
    w1_t[3]  = salt_buf_t1[1];
    w2_t[0]  = salt_buf_t1[2];
    w2_t[1]  = salt_buf_t1[3];
    w2_t[2]  = salt_buf_t1[4];

    // 41..46
    w2_t[2] |= digest_t1[0];
    w2_t[3]  = digest_t1[1];

    // 46..62
    w2_t[3] |= salt_buf_t2[0];
    w3_t[0]  = salt_buf_t2[1];
    w3_t[1]  = salt_buf_t2[2];
    w3_t[2]  = salt_buf_t2[3];
    w3_t[3]  = salt_buf_t2[4];

    // 62..
    w3_t[3] |= digest_t2[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..3
    w0_t[0]  = digest_t2[1];

    // 3..19
    w0_t[0] |= salt_buf_t3[0];
    w0_t[1]  = salt_buf_t3[1];
    w0_t[2]  = salt_buf_t3[2];
    w0_t[3]  = salt_buf_t3[3];
    w1_t[0]  = salt_buf_t3[4];

    // 19..24
    w1_t[0] |= digest_t3[0];
    w1_t[1]  = digest_t3[1];

    // 24..40
    w1_t[2]  = salt_buf_t0[0];
    w1_t[3]  = salt_buf_t0[1];
    w2_t[0]  = salt_buf_t0[2];
    w2_t[1]  = salt_buf_t0[3];

    // 40..45
    w2_t[2]  = digest_t0[0];
    w2_t[3]  = digest_t0[1];

    // 45..61
    w2_t[3] |= salt_buf_t1[0];
    w3_t[0]  = salt_buf_t1[1];
    w3_t[1]  = salt_buf_t1[2];
    w3_t[2]  = salt_buf_t1[3];
    w3_t[3]  = salt_buf_t1[4];

    // 61..
    w3_t[3] |= digest_t1[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..2
    w0_t[0]  = digest_t1[1];

    // 2..18
    w0_t[0] |= salt_buf_t2[0];
    w0_t[1]  = salt_buf_t2[1];
    w0_t[2]  = salt_buf_t2[2];
    w0_t[3]  = salt_buf_t2[3];
    w1_t[0]  = salt_buf_t2[4];

    // 18..23
    w1_t[0] |= digest_t2[0];
    w1_t[1]  = digest_t2[1];

    // 23..39
    w1_t[1] |= salt_buf_t3[0];
    w1_t[2]  = salt_buf_t3[1];
    w1_t[3]  = salt_buf_t3[2];
    w2_t[0]  = salt_buf_t3[3];
    w2_t[1]  = salt_buf_t3[4];

    // 39..44
    w2_t[1] |= digest_t3[0];
    w2_t[2]  = digest_t3[1];

    // 44..60
    w2_t[3]  = salt_buf_t0[0];
    w3_t[0]  = salt_buf_t0[1];
    w3_t[1]  = salt_buf_t0[2];
    w3_t[2]  = salt_buf_t0[3];

    // 60..
    w3_t[3]  = digest_t0[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..1
    w0_t[0]  = digest_t0[1];

    // 1..17
    w0_t[0] |= salt_buf_t1[0];
    w0_t[1]  = salt_buf_t1[1];
    w0_t[2]  = salt_buf_t1[2];
    w0_t[3]  = salt_buf_t1[3];
    w1_t[0]  = salt_buf_t1[4];

    // 17..22
    w1_t[0] |= digest_t1[0];
    w1_t[1]  = digest_t1[1];

    // 22..38
    w1_t[1] |= salt_buf_t2[0];
    w1_t[2]  = salt_buf_t2[1];
    w1_t[3]  = salt_buf_t2[2];
    w2_t[0]  = salt_buf_t2[3];
    w2_t[1]  = salt_buf_t2[4];

    // 38..43
    w2_t[1] |= digest_t2[0];
    w2_t[2]  = digest_t2[1];

    // 43..59
    w2_t[2] |= salt_buf_t3[0];
    w2_t[3]  = salt_buf_t3[1];
    w3_t[0]  = salt_buf_t3[2];
    w3_t[1]  = salt_buf_t3[3];
    w3_t[2]  = salt_buf_t3[4];

    // 59..
    w3_t[2] |= digest_t3[0];
    w3_t[3]  = digest_t3[1];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0]  = salt_buf_t0[0];
    w0_t[1]  = salt_buf_t0[1];
    w0_t[2]  = salt_buf_t0[2];
    w0_t[3]  = salt_buf_t0[3];
    w1_t[0]  = 0x80;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 21 * 16 * 8;
    w3_t[3]  = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the 40 bit input for the MD5 which then will generate the RC4 key, so it's precomputable!

    w0_t[0]  = digest[0];
    w0_t[1]  = digest[1] & 0xff;
    w0_t[2]  = 0x8000;
    w0_t[3]  = 0;
    w1_t[0]  = 0;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 9 * 8;
    w3_t[3]  = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0_t[0] = out[0];
    w0_t[1] = out[1];
    w0_t[2] = out[2];
    w0_t[3] = out[3];
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
    w3_t[2] = 16 * 8;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    rc4_next_16 (S, 16, j, digest, out, lid);

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

DECLSPEC void m09700s (LOCAL_AS u32 *S, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_ESALT (oldoffice01_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf_t0[4];

  salt_buf_t0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf_t0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf_t0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf_t0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  u32 salt_buf_t1[5];

  salt_buf_t1[0] = hc_bytealign_S (            0, salt_buf_t0[0], 1);
  salt_buf_t1[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 1);
  salt_buf_t1[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 1);
  salt_buf_t1[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 1);
  salt_buf_t1[4] = hc_bytealign_S (salt_buf_t0[3],             0, 1);

  u32 salt_buf_t2[5];

  salt_buf_t2[0] = hc_bytealign_S (            0, salt_buf_t0[0], 2);
  salt_buf_t2[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 2);
  salt_buf_t2[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 2);
  salt_buf_t2[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 2);
  salt_buf_t2[4] = hc_bytealign_S (salt_buf_t0[3],             0, 2);

  u32 salt_buf_t3[5];

  salt_buf_t3[0] = hc_bytealign_S (            0, salt_buf_t0[0], 3);
  salt_buf_t3[1] = hc_bytealign_S (salt_buf_t0[0], salt_buf_t0[1], 3);
  salt_buf_t3[2] = hc_bytealign_S (salt_buf_t0[1], salt_buf_t0[2], 3);
  salt_buf_t3[3] = hc_bytealign_S (salt_buf_t0[2], salt_buf_t0[3], 3);
  salt_buf_t3[4] = hc_bytealign_S (salt_buf_t0[3],             0, 3);

  /**
   * esalt
   */

  u32 encryptedVerifier[4];

  encryptedVerifier[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[0];
  encryptedVerifier[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[1];
  encryptedVerifier[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[2];
  encryptedVerifier[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encryptedVerifier[3];

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
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = ix_create_bft (bfs_buf, il_pos);

    const u32 w0lr = w0l | w0r;

    /**
     * md5
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    w0_t[0] = w0lr;
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = w2[0];
    w2_t[1] = w2[1];
    w2_t[2] = w2[2];
    w2_t[3] = w2[3];
    w3_t[0] = w3[0];
    w3_t[1] = w3[1];
    w3_t[2] = pw_len * 8;
    w3_t[3] = 0;

    u32 digest_t0[4];
    u32 digest_t1[2]; // need only first 5 byte
    u32 digest_t2[2];
    u32 digest_t3[2];

    digest_t0[0] = MD5M_A;
    digest_t0[1] = MD5M_B;
    digest_t0[2] = MD5M_C;
    digest_t0[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest_t0);

    // prepare 16 * 21 buffer stuff

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    // offsets

    digest_t0[0] &= 0xffffffff;
    digest_t0[1] &= 0x000000ff;
    digest_t0[2] &= 0x00000000;
    digest_t0[3] &= 0x00000000;

    digest_t1[0] = hc_bytealign_S (           0, digest_t0[0], 1);
    digest_t1[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 1);

    digest_t2[0] = hc_bytealign_S (           0, digest_t0[0], 2);
    digest_t2[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 2);

    digest_t3[0] = hc_bytealign_S (           0, digest_t0[0], 3);
    digest_t3[1] = hc_bytealign_S (digest_t0[0], digest_t0[1], 3);

    // generate the 16 * 21 buffer

    // 0..5
    w0_t[0]  = digest_t0[0];
    w0_t[1]  = digest_t0[1];

    // 5..21
    w0_t[1] |= salt_buf_t1[0];
    w0_t[2]  = salt_buf_t1[1];
    w0_t[3]  = salt_buf_t1[2];
    w1_t[0]  = salt_buf_t1[3];
    w1_t[1]  = salt_buf_t1[4];

    // 21..26
    w1_t[1] |= digest_t1[0];
    w1_t[2]  = digest_t1[1];

    // 26..42
    w1_t[2] |= salt_buf_t2[0];
    w1_t[3]  = salt_buf_t2[1];
    w2_t[0]  = salt_buf_t2[2];
    w2_t[1]  = salt_buf_t2[3];
    w2_t[2]  = salt_buf_t2[4];

    // 42..47
    w2_t[2] |= digest_t2[0];
    w2_t[3]  = digest_t2[1];

    // 47..63
    w2_t[3] |= salt_buf_t3[0];
    w3_t[0]  = salt_buf_t3[1];
    w3_t[1]  = salt_buf_t3[2];
    w3_t[2]  = salt_buf_t3[3];
    w3_t[3]  = salt_buf_t3[4];

    // 63..

    w3_t[3] |= digest_t3[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..4
    w0_t[0]  = digest_t3[1];

    // 4..20
    w0_t[1]  = salt_buf_t0[0];
    w0_t[2]  = salt_buf_t0[1];
    w0_t[3]  = salt_buf_t0[2];
    w1_t[0]  = salt_buf_t0[3];

    // 20..25
    w1_t[1]  = digest_t0[0];
    w1_t[2]  = digest_t0[1];

    // 25..41
    w1_t[2] |= salt_buf_t1[0];
    w1_t[3]  = salt_buf_t1[1];
    w2_t[0]  = salt_buf_t1[2];
    w2_t[1]  = salt_buf_t1[3];
    w2_t[2]  = salt_buf_t1[4];

    // 41..46
    w2_t[2] |= digest_t1[0];
    w2_t[3]  = digest_t1[1];

    // 46..62
    w2_t[3] |= salt_buf_t2[0];
    w3_t[0]  = salt_buf_t2[1];
    w3_t[1]  = salt_buf_t2[2];
    w3_t[2]  = salt_buf_t2[3];
    w3_t[3]  = salt_buf_t2[4];

    // 62..
    w3_t[3] |= digest_t2[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..3
    w0_t[0]  = digest_t2[1];

    // 3..19
    w0_t[0] |= salt_buf_t3[0];
    w0_t[1]  = salt_buf_t3[1];
    w0_t[2]  = salt_buf_t3[2];
    w0_t[3]  = salt_buf_t3[3];
    w1_t[0]  = salt_buf_t3[4];

    // 19..24
    w1_t[0] |= digest_t3[0];
    w1_t[1]  = digest_t3[1];

    // 24..40
    w1_t[2]  = salt_buf_t0[0];
    w1_t[3]  = salt_buf_t0[1];
    w2_t[0]  = salt_buf_t0[2];
    w2_t[1]  = salt_buf_t0[3];

    // 40..45
    w2_t[2]  = digest_t0[0];
    w2_t[3]  = digest_t0[1];

    // 45..61
    w2_t[3] |= salt_buf_t1[0];
    w3_t[0]  = salt_buf_t1[1];
    w3_t[1]  = salt_buf_t1[2];
    w3_t[2]  = salt_buf_t1[3];
    w3_t[3]  = salt_buf_t1[4];

    // 61..
    w3_t[3] |= digest_t1[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..2
    w0_t[0]  = digest_t1[1];

    // 2..18
    w0_t[0] |= salt_buf_t2[0];
    w0_t[1]  = salt_buf_t2[1];
    w0_t[2]  = salt_buf_t2[2];
    w0_t[3]  = salt_buf_t2[3];
    w1_t[0]  = salt_buf_t2[4];

    // 18..23
    w1_t[0] |= digest_t2[0];
    w1_t[1]  = digest_t2[1];

    // 23..39
    w1_t[1] |= salt_buf_t3[0];
    w1_t[2]  = salt_buf_t3[1];
    w1_t[3]  = salt_buf_t3[2];
    w2_t[0]  = salt_buf_t3[3];
    w2_t[1]  = salt_buf_t3[4];

    // 39..44
    w2_t[1] |= digest_t3[0];
    w2_t[2]  = digest_t3[1];

    // 44..60
    w2_t[3]  = salt_buf_t0[0];
    w3_t[0]  = salt_buf_t0[1];
    w3_t[1]  = salt_buf_t0[2];
    w3_t[2]  = salt_buf_t0[3];

    // 60..
    w3_t[3]  = digest_t0[0];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // 0..1
    w0_t[0]  = digest_t0[1];

    // 1..17
    w0_t[0] |= salt_buf_t1[0];
    w0_t[1]  = salt_buf_t1[1];
    w0_t[2]  = salt_buf_t1[2];
    w0_t[3]  = salt_buf_t1[3];
    w1_t[0]  = salt_buf_t1[4];

    // 17..22
    w1_t[0] |= digest_t1[0];
    w1_t[1]  = digest_t1[1];

    // 22..38
    w1_t[1] |= salt_buf_t2[0];
    w1_t[2]  = salt_buf_t2[1];
    w1_t[3]  = salt_buf_t2[2];
    w2_t[0]  = salt_buf_t2[3];
    w2_t[1]  = salt_buf_t2[4];

    // 38..43
    w2_t[1] |= digest_t2[0];
    w2_t[2]  = digest_t2[1];

    // 43..59
    w2_t[2] |= salt_buf_t3[0];
    w2_t[3]  = salt_buf_t3[1];
    w3_t[0]  = salt_buf_t3[2];
    w3_t[1]  = salt_buf_t3[3];
    w3_t[2]  = salt_buf_t3[4];

    // 59..
    w3_t[2] |= digest_t3[0];
    w3_t[3]  = digest_t3[1];

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0]  = salt_buf_t0[0];
    w0_t[1]  = salt_buf_t0[1];
    w0_t[2]  = salt_buf_t0[2];
    w0_t[3]  = salt_buf_t0[3];
    w1_t[0]  = 0x80;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 21 * 16 * 8;
    w3_t[3]  = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the 40 bit input for the MD5 which then will generate the RC4 key, so it's precomputable!

    w0_t[0]  = digest[0];
    w0_t[1]  = digest[1] & 0xff;
    w0_t[2]  = 0x8000;
    w0_t[3]  = 0;
    w1_t[0]  = 0;
    w1_t[1]  = 0;
    w1_t[2]  = 0;
    w1_t[3]  = 0;
    w2_t[0]  = 0;
    w2_t[1]  = 0;
    w2_t[2]  = 0;
    w2_t[3]  = 0;
    w3_t[0]  = 0;
    w3_t[1]  = 0;
    w3_t[2]  = 9 * 8;
    w3_t[3]  = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    // now the RC4 part

    rc4_init_128 (S, digest, lid);

    u32 out[4];

    u8 j = rc4_next_16 (S, 0, 0, encryptedVerifier, out, lid);

    w0_t[0] = out[0];
    w0_t[1] = out[1];
    w0_t[2] = out[2];
    w0_t[3] = out[3];
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
    w3_t[2] = 16 * 8;
    w3_t[3] = 0;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    m09700_md5_transform_early (w0_t, w1_t, w2_t, w3_t, digest);

    if (m09700_rc4_next_16_early (S, 16, j, digest, out[2], out, search[0], lid) == 0) continue;

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m09700_m04 (KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
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

  m09700m (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m09700_m08 (KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
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

  m09700m (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m09700_m16 (KERN_ATTR_ESALT (oldoffice01_t))
{
}

KERNEL_FQ KERNEL_FA void m09700_s04 (KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
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

  m09700s (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m09700_s08 (KERN_ATTR_ESALT (oldoffice01_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
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

  m09700s (S, w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m09700_s16 (KERN_ATTR_ESALT (oldoffice01_t))
{
}
