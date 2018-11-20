/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define ROUNDS 0x40000

#define PUTCHAR(a,p,c) ((u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)   ((u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((u8 *)(a))[(p) ^ 3]

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

DECLSPEC void sha1_transform (const u32 *w, u32 *digest)
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = w[ 0];
  u32 w1_t = w[ 1];
  u32 w2_t = w[ 2];
  u32 w3_t = w[ 3];
  u32 w4_t = w[ 4];
  u32 w5_t = w[ 5];
  u32 w6_t = w[ 6];
  u32 w7_t = w[ 7];
  u32 w8_t = w[ 8];
  u32 w9_t = w[ 9];
  u32 wa_t = w[10];
  u32 wb_t = w[11];
  u32 wc_t = w[12];
  u32 wd_t = w[13];
  u32 we_t = w[14];
  u32 wf_t = w[15];

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

__kernel void m12500_init (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, pbkdf2_sha1_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  tmps[gid].dgst[0][0] = SHA1M_A;
  tmps[gid].dgst[0][1] = SHA1M_B;
  tmps[gid].dgst[0][2] = SHA1M_C;
  tmps[gid].dgst[0][3] = SHA1M_D;
  tmps[gid].dgst[0][4] = SHA1M_E;
}

__kernel void m12500_loop (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, pbkdf2_sha1_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf[5];

  pw_buf[0] = pws[gid].i[0];
  pw_buf[1] = pws[gid].i[1];
  pw_buf[2] = pws[gid].i[2];
  pw_buf[3] = pws[gid].i[3];
  pw_buf[4] = pws[gid].i[4];

  const u32 pw_len = MIN (pws[gid].pw_len, 20);

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];

  const u32 salt_len = 8;

  // this is large enough to hold all possible w[] arrays for 64 iterations

  #define LARGEBLOCK_ELEMS ((40 + 8 + 3) * 16)

  u32 largeblock[LARGEBLOCK_ELEMS];

  for (u32 i = 0; i < LARGEBLOCK_ELEMS; i++) largeblock[i] = 0;

  for (u32 i = 0, p = 0; i < 64; i++)
  {
    for (u32 j = 0; j < pw_len; j++, p += 2)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (salt_buf, j));
    }

    PUTCHAR_BE (largeblock, p + 2, (loop_pos >> 16) & 0xff);

    p += 3;
  }

  const u32 p3 = (pw_len * 2) + salt_len + 3;

  const u32 init_pos = loop_pos / (ROUNDS / 16);

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[init_pos][0];
  dgst[1] = tmps[gid].dgst[init_pos][1];
  dgst[2] = tmps[gid].dgst[init_pos][2];
  dgst[3] = tmps[gid].dgst[init_pos][3];
  dgst[4] = tmps[gid].dgst[init_pos][4];

  u32 iter = loop_pos;

  for (u32 i = 0; i < 256; i += 4)
  {
    for (u32 j = 0; j < 64; j++)
    {
      const u32 p = ((j + 1) * p3) - 2;

      PUTCHAR_BE (largeblock, p, iter >> 8);
    }

    for (u32 k = 0; k < 4; k++)
    {
      for (u32 j = 0; j < 64; j++)
      {
        const u32 p = ((j + 1) * p3) - 3;

        PUTCHAR_BE (largeblock, p, iter >> 0);

        iter++;
      }

      for (u32 j = 0; j < p3; j++)
      {
        const u32 j16 = j * 16;

        sha1_transform (&largeblock[j16], dgst);
      }
    }
  }

  tmps[gid].dgst[init_pos + 1][0] = dgst[0];
  tmps[gid].dgst[init_pos + 1][1] = dgst[1];
  tmps[gid].dgst[init_pos + 1][2] = dgst[2];
  tmps[gid].dgst[init_pos + 1][3] = dgst[3];
  tmps[gid].dgst[init_pos + 1][4] = dgst[4];
}

__kernel void m12500_comp (KERN_ATTR_TMPS_ESALT (rar3_tmp_t, pbkdf2_sha1_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = MIN (pws[gid].pw_len, 20);

  const u32 salt_len = 8;

  const u32 p3 = (pw_len * 2) + salt_len + 3;

  u32 w_buf[16];

  w_buf[ 0] = 0x80000000;
  w_buf[ 1] = 0;
  w_buf[ 2] = 0;
  w_buf[ 3] = 0;
  w_buf[ 4] = 0;
  w_buf[ 5] = 0;
  w_buf[ 6] = 0;
  w_buf[ 7] = 0;
  w_buf[ 8] = 0;
  w_buf[ 9] = 0;
  w_buf[10] = 0;
  w_buf[11] = 0;
  w_buf[12] = 0;
  w_buf[13] = 0;
  w_buf[14] = 0;
  w_buf[15] = (p3 * ROUNDS) * 8;

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[16][0];
  dgst[1] = tmps[gid].dgst[16][1];
  dgst[2] = tmps[gid].dgst[16][2];
  dgst[3] = tmps[gid].dgst[16][3];
  dgst[4] = tmps[gid].dgst[16][4];

  sha1_transform (w_buf, dgst);

  u32 ukey[4];

  ukey[0] = swap32_S (dgst[0]);
  ukey[1] = swap32_S (dgst[1]);
  ukey[2] = swap32_S (dgst[2]);
  ukey[3] = swap32_S (dgst[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 data[4];

  data[0] = salt_bufs[salt_pos].salt_buf[2];
  data[1] = salt_bufs[salt_pos].salt_buf[3];
  data[2] = salt_bufs[salt_pos].salt_buf[4];
  data[3] = salt_bufs[salt_pos].salt_buf[5];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 iv[4];

  iv[0] = 0;
  iv[1] = 0;
  iv[2] = 0;
  iv[3] = 0;

  for (int i = 0; i < 16; i++)
  {
    u32 pw_buf[5];

    pw_buf[0] = pws[gid].i[0];
    pw_buf[1] = pws[gid].i[1];
    pw_buf[2] = pws[gid].i[2];
    pw_buf[3] = pws[gid].i[3];
    pw_buf[4] = pws[gid].i[4];

    //const u32 pw_len = pws[gid].pw_len & 255;

    u32 salt_buf[2];

    salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
    salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];

    //const u32 salt_len = 8;

    //const u32 p3 = (pw_len * 2) + salt_len + 3;

    u32 w[16];

    w[ 0] = 0;
    w[ 1] = 0;
    w[ 2] = 0;
    w[ 3] = 0;
    w[ 4] = 0;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u32 p = 0;

    for (u32 j = 0; j < pw_len; j++, p += 2)
    {
      PUTCHAR_BE (w, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (w, p, GETCHAR (salt_buf, j));
    }

    const u32 iter_pos = i * (ROUNDS / 16);

    PUTCHAR_BE (w, p + 0, (iter_pos >>  0) & 0xff);
    PUTCHAR_BE (w, p + 1, (iter_pos >>  8) & 0xff);
    PUTCHAR_BE (w, p + 2, (iter_pos >> 16) & 0xff);

    PUTCHAR_BE (w, p3, 0x80);

    w[15] = ((iter_pos + 1) * p3) * 8;

    u32 dgst[5];

    dgst[0] = tmps[gid].dgst[i][0];
    dgst[1] = tmps[gid].dgst[i][1];
    dgst[2] = tmps[gid].dgst[i][2];
    dgst[3] = tmps[gid].dgst[i][3];
    dgst[4] = tmps[gid].dgst[i][4];

    sha1_transform (w, dgst);

    PUTCHAR (iv, i, dgst[4] & 0xff);
  }

  out[0] ^= swap32_S (iv[0]);
  out[1] ^= swap32_S (iv[1]);
  out[2] ^= swap32_S (iv[2]);
  out[3] ^= swap32_S (iv[3]);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #include COMPARE_M
}
