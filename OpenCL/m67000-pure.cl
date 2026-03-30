/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_yescrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

DECLSPEC void yescrypt_pbkdf2_sha256 (PRIVATE_AS const u32 *pw, const u32 pw_len, PRIVATE_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out, const u32 out_len)
{
  sha256_hmac_ctx_t hmac_ctx;

  sha256_hmac_init_swap (&hmac_ctx, pw, pw_len);
  sha256_hmac_update_swap (&hmac_ctx, salt_buf, salt_len);

  for (u32 i = 0, blk = 1; i < out_len; i += 32, blk++)
  {
    sha256_hmac_ctx_t hmac_ctx2 = hmac_ctx;

    u32 w0[4], w1[4], w2[4], w3[4];

    w0[0] = blk;
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

    sha256_hmac_update_64 (&hmac_ctx2, w0, w1, w2, w3, 4);
    sha256_hmac_final (&hmac_ctx2);

    const u32 remain = (out_len - i < 32) ? out_len - i : 32;

    if (remain >=  4) out[i / 4 + 0] = hc_swap32_S (hmac_ctx2.opad.h[0]);
    if (remain >=  8) out[i / 4 + 1] = hc_swap32_S (hmac_ctx2.opad.h[1]);
    if (remain >= 12) out[i / 4 + 2] = hc_swap32_S (hmac_ctx2.opad.h[2]);
    if (remain >= 16) out[i / 4 + 3] = hc_swap32_S (hmac_ctx2.opad.h[3]);
    if (remain >= 20) out[i / 4 + 4] = hc_swap32_S (hmac_ctx2.opad.h[4]);
    if (remain >= 24) out[i / 4 + 5] = hc_swap32_S (hmac_ctx2.opad.h[5]);
    if (remain >= 28) out[i / 4 + 6] = hc_swap32_S (hmac_ctx2.opad.h[6]);
    if (remain >= 32) out[i / 4 + 7] = hc_swap32_S (hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void yescrypt_pbkdf2_sha256_global_salt (PRIVATE_AS const u32 *pw, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out, const u32 out_len)
{
  sha256_hmac_ctx_t hmac_ctx;

  sha256_hmac_init_swap (&hmac_ctx, pw, pw_len);
  sha256_hmac_update_global_swap (&hmac_ctx, salt_buf, salt_len);

  for (u32 i = 0, blk = 1; i < out_len; i += 32, blk++)
  {
    sha256_hmac_ctx_t hmac_ctx2 = hmac_ctx;

    u32 w0[4], w1[4], w2[4], w3[4];

    w0[0] = blk;
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

    sha256_hmac_update_64 (&hmac_ctx2, w0, w1, w2, w3, 4);
    sha256_hmac_final (&hmac_ctx2);

    const u32 remain = (out_len - i < 32) ? out_len - i : 32;

    if (remain >=  4) out[i / 4 + 0] = hc_swap32_S (hmac_ctx2.opad.h[0]);
    if (remain >=  8) out[i / 4 + 1] = hc_swap32_S (hmac_ctx2.opad.h[1]);
    if (remain >= 12) out[i / 4 + 2] = hc_swap32_S (hmac_ctx2.opad.h[2]);
    if (remain >= 16) out[i / 4 + 3] = hc_swap32_S (hmac_ctx2.opad.h[3]);
    if (remain >= 20) out[i / 4 + 4] = hc_swap32_S (hmac_ctx2.opad.h[4]);
    if (remain >= 24) out[i / 4 + 5] = hc_swap32_S (hmac_ctx2.opad.h[5]);
    if (remain >= 28) out[i / 4 + 6] = hc_swap32_S (hmac_ctx2.opad.h[6]);
    if (remain >= 32) out[i / 4 + 7] = hc_swap32_S (hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void yescrypt_initial_hmac (PRIVATE_AS const u32 *hmac_key, const u32 hmac_key_len, GLOBAL_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *passwd)
{
  sha256_hmac_ctx_t hmac_ctx;

  sha256_hmac_init_swap (&hmac_ctx, hmac_key, hmac_key_len);
  sha256_hmac_update_global_swap (&hmac_ctx, msg_buf, msg_len);
  sha256_hmac_final (&hmac_ctx);

  passwd[0] = hc_swap32_S (hmac_ctx.opad.h[0]);
  passwd[1] = hc_swap32_S (hmac_ctx.opad.h[1]);
  passwd[2] = hc_swap32_S (hmac_ctx.opad.h[2]);
  passwd[3] = hc_swap32_S (hmac_ctx.opad.h[3]);
  passwd[4] = hc_swap32_S (hmac_ctx.opad.h[4]);
  passwd[5] = hc_swap32_S (hmac_ctx.opad.h[5]);
  passwd[6] = hc_swap32_S (hmac_ctx.opad.h[6]);
  passwd[7] = hc_swap32_S (hmac_ctx.opad.h[7]);
}

DECLSPEC void yescrypt_private_hmac (PRIVATE_AS const u32 *hmac_key, const u32 hmac_key_len, PRIVATE_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *passwd)
{
  sha256_hmac_ctx_t hmac_ctx;

  sha256_hmac_init_swap (&hmac_ctx, hmac_key, hmac_key_len);
  sha256_hmac_update_swap (&hmac_ctx, msg_buf, msg_len);
  sha256_hmac_final (&hmac_ctx);

  passwd[0] = hc_swap32_S (hmac_ctx.opad.h[0]);
  passwd[1] = hc_swap32_S (hmac_ctx.opad.h[1]);
  passwd[2] = hc_swap32_S (hmac_ctx.opad.h[2]);
  passwd[3] = hc_swap32_S (hmac_ctx.opad.h[3]);
  passwd[4] = hc_swap32_S (hmac_ctx.opad.h[4]);
  passwd[5] = hc_swap32_S (hmac_ctx.opad.h[5]);
  passwd[6] = hc_swap32_S (hmac_ctx.opad.h[6]);
  passwd[7] = hc_swap32_S (hmac_ctx.opad.h[7]);
}

DECLSPEC void yescrypt_kdf_setup (GLOBAL_AS const u32 *salt_buf_g, const u32 salt_len, PRIVATE_AS u32 *passwd, PRIVATE_AS u32 *B, LOCAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr)
{
  yescrypt_pbkdf2_sha256_global_salt (passwd, 32, salt_buf_g, salt_len, B, YESCRYPT_STATE_SZ);

  for (u32 j = 0; j < 8; j++) passwd[j] = B[j];

  {
    u32 B_r1[32];

    for (u32 j = 0; j < 32; j++) B_r1[j] = B[j];

    yescrypt_sbox_init (B_r1, sbox, 1);

    for (u32 j = 0; j < 32; j++) B[j] = B_r1[j];
  }

  *s_state = 0;
  *w_ptr = 0;

  {
    u32 b_tail[16];

    for (u32 j = 0; j < 16; j++)
      b_tail[j] = B[YESCRYPT_STATE_CNT4 - 16 + j];

    sha256_hmac_ctx_t hmac_fb;

    sha256_hmac_init_swap (&hmac_fb, b_tail, 64);
    sha256_hmac_update_swap (&hmac_fb, passwd, 32);
    sha256_hmac_final (&hmac_fb);

    passwd[0] = hc_swap32_S (hmac_fb.opad.h[0]);
    passwd[1] = hc_swap32_S (hmac_fb.opad.h[1]);
    passwd[2] = hc_swap32_S (hmac_fb.opad.h[2]);
    passwd[3] = hc_swap32_S (hmac_fb.opad.h[3]);
    passwd[4] = hc_swap32_S (hmac_fb.opad.h[4]);
    passwd[5] = hc_swap32_S (hmac_fb.opad.h[5]);
    passwd[6] = hc_swap32_S (hmac_fb.opad.h[6]);
    passwd[7] = hc_swap32_S (hmac_fb.opad.h[7]);
  }

  {
    u32 B_tmp[YESCRYPT_STATE_CNT4];

    for (u32 j = 0; j < YESCRYPT_STATE_CNT4; j++) B_tmp[j] = B[j];

    yescrypt_simd_shuffle (B_tmp, B, YESCRYPT_R);
  }
}

DECLSPEC void yescrypt_prehash_smix (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, LOCAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 prehash_N, const u32 flags)
{
  for (u32 i = 0; i < prehash_N; i++)
  {
    yescrypt_smix1_step (X, V, sbox, s_state, w_ptr, r, prehash_N, i, flags);
  }

  u32 Nloop_rw = (prehash_N + 2) / 3;
  Nloop_rw++;
  Nloop_rw &= ~(u32) 1;

  for (u32 i = 0; i < Nloop_rw; i++)
  {
    yescrypt_smix2_step (X, V, sbox, s_state, w_ptr, r, prehash_N, flags);
  }
}

KERNEL_FQ KERNEL_FA void m67000_init (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_AS u32 sbox[Swords];

  u32 hmac_key[16];

  hmac_key[ 0] = 0x63736579; // "yesc" LE
  hmac_key[ 1] = 0x74707972; // "rypt" LE
  hmac_key[ 2] = 0;
  hmac_key[ 3] = 0;
  hmac_key[ 4] = 0;
  hmac_key[ 5] = 0;
  hmac_key[ 6] = 0;
  hmac_key[ 7] = 0;
  hmac_key[ 8] = 0;
  hmac_key[ 9] = 0;
  hmac_key[10] = 0;
  hmac_key[11] = 0;
  hmac_key[12] = 0;
  hmac_key[13] = 0;
  hmac_key[14] = 0;
  hmac_key[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  u32 passwd[16];

  passwd[ 0] = 0;
  passwd[ 1] = 0;
  passwd[ 2] = 0;
  passwd[ 3] = 0;
  passwd[ 4] = 0;
  passwd[ 5] = 0;
  passwd[ 6] = 0;
  passwd[ 7] = 0;
  passwd[ 8] = 0;
  passwd[ 9] = 0;
  passwd[10] = 0;
  passwd[11] = 0;
  passwd[12] = 0;
  passwd[13] = 0;
  passwd[14] = 0;
  passwd[15] = 0;

  u32 B[YESCRYPT_STATE_CNT4];

  u32 s_state = 0;
  u32 w = 0;

  const u32 gid_d4 = gid / 4;
  const u32 gid_m4 = gid & 3;

  GLOBAL_AS u32 *V;

  switch (gid_m4)
  {
    case 0: V = (GLOBAL_AS u32 *) d_extra0_buf; break;
    case 1: V = (GLOBAL_AS u32 *) d_extra1_buf; break;
    case 2: V = (GLOBAL_AS u32 *) d_extra2_buf; break;
    case 3: V = (GLOBAL_AS u32 *) d_extra3_buf; break;
  }

  V += gid_d4 * YESCRYPT_STATE_CNT4 * YESCRYPT_N;

  #if YESCRYPT_PREHASH_NEEDED

  hmac_key[2] = 0x6572702d; // "-pre" LE
  hmac_key[3] = 0x68736168; // "hash" LE
  yescrypt_initial_hmac (hmac_key, 16, pws[gid].i, pw_len, passwd);
  hmac_key[2] = 0;
  hmac_key[3] = 0;

  yescrypt_kdf_setup (salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, passwd, B, sbox, &s_state, &w);

  yescrypt_prehash_smix (B, V, sbox, &s_state, &w, YESCRYPT_R, YESCRYPT_PREHASH_N, YESCRYPT_FLAGS);

  {
    u32 B_unshuffled[YESCRYPT_STATE_CNT4];

    yescrypt_simd_unshuffle (B, B_unshuffled, YESCRYPT_R);

    u32 dk[8];

    yescrypt_pbkdf2_sha256 (passwd, 32, B_unshuffled, YESCRYPT_STATE_SZ, dk, 32);

    for (u32 i = 0; i < 8; i++) passwd[i] = dk[i];
  }

  yescrypt_private_hmac (hmac_key, 8, passwd, 32, passwd);

  #else

  yescrypt_initial_hmac (hmac_key, 8, pws[gid].i, pw_len, passwd);

  #endif

  yescrypt_kdf_setup (salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, passwd, B, sbox, &s_state, &w);

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) tmps[gid].P[i] = B[i];

  for (u32 i = 0; i < Swords; i++) tmps[gid].S[i] = sbox[i];

  for (u32 i = 0; i < 8; i++) tmps[gid].passwd[i] = passwd[i];

  tmps[gid].phase   = 0;
  tmps[gid].iter    = 0;
  tmps[gid].s_state = s_state;
  tmps[gid].w       = w;
}

KERNEL_FQ KERNEL_FA void m67000_loop (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  LOCAL_AS u32 sbox[Swords];

  u32 X[YESCRYPT_STATE_CNT4];

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) X[i] = tmps[gid].P[i];

  for (u32 i = 0; i < Swords; i++) sbox[i] = tmps[gid].S[i];

  u32 phase   = tmps[gid].phase;
  u32 iter    = tmps[gid].iter;
  u32 s_state = tmps[gid].s_state;
  u32 w       = tmps[gid].w;

  const u32 gid_d4 = gid / 4;
  const u32 gid_m4 = gid & 3;

  GLOBAL_AS u32 *V;

  switch (gid_m4)
  {
    case 0: V = (GLOBAL_AS u32 *) d_extra0_buf; break;
    case 1: V = (GLOBAL_AS u32 *) d_extra1_buf; break;
    case 2: V = (GLOBAL_AS u32 *) d_extra2_buf; break;
    case 3: V = (GLOBAL_AS u32 *) d_extra3_buf; break;
  }

  V += gid_d4 * YESCRYPT_STATE_CNT4 * YESCRYPT_N;

  for (u32 loop = 0; loop < LOOP_CNT; loop++)
  {
    if (phase == 0)
    {
      if (iter < YESCRYPT_N)
      {
        yescrypt_smix1_step (X, V, sbox, &s_state, &w, YESCRYPT_R, YESCRYPT_N, iter, YESCRYPT_FLAGS);
        iter++;

        if (iter >= YESCRYPT_N)
        {
          phase = 1;
          iter = 0;
        }
      }
    }
    else if (phase == 1)
    {
      if (iter < YESCRYPT_NLOOP_RW)
      {
        yescrypt_smix2_step (X, V, sbox, &s_state, &w, YESCRYPT_R, YESCRYPT_N, YESCRYPT_FLAGS);
        iter++;
      }
      else
      {
        break;
      }
    }
  }

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) tmps[gid].P[i] = X[i];

  for (u32 i = 0; i < Swords; i++) tmps[gid].S[i] = sbox[i];

  tmps[gid].phase   = phase;
  tmps[gid].iter    = iter;
  tmps[gid].s_state = s_state;
  tmps[gid].w       = w;
}

KERNEL_FQ KERNEL_FA void m67000_comp (KERN_ATTR_TMPS_ESALT (yescrypt_tmp_t, void))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 X[YESCRYPT_STATE_CNT4];

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) X[i] = tmps[gid].P[i];

  u32 passwd[16];

  for (u32 i = 0; i < 8; i++) passwd[i] = tmps[gid].passwd[i];
  for (u32 i = 8; i < 16; i++) passwd[i] = 0;

  u32 B[YESCRYPT_STATE_CNT4];

  yescrypt_simd_unshuffle (X, B, YESCRYPT_R);

  u32 dk[16];

  for (u32 i = 0; i < 16; i++) dk[i] = 0;

  yescrypt_pbkdf2_sha256 (passwd, 32, B, YESCRYPT_STATE_SZ, dk, 32);

  #if (YESCRYPT_FLAGS != 0)
  {
    u32 client_key_msg[16];

    client_key_msg[ 0] = 0x65696c43; // "Clie" LE
    client_key_msg[ 1] = 0x4b20746e; // "nt K" LE
    client_key_msg[ 2] = 0x00007965; // "ey\0\0" LE
    client_key_msg[ 3] = 0;
    client_key_msg[ 4] = 0;
    client_key_msg[ 5] = 0;
    client_key_msg[ 6] = 0;
    client_key_msg[ 7] = 0;
    client_key_msg[ 8] = 0;
    client_key_msg[ 9] = 0;
    client_key_msg[10] = 0;
    client_key_msg[11] = 0;
    client_key_msg[12] = 0;
    client_key_msg[13] = 0;
    client_key_msg[14] = 0;
    client_key_msg[15] = 0;

    sha256_hmac_ctx_t hmac_ck;

    sha256_hmac_init_swap (&hmac_ck, dk, 32);
    sha256_hmac_update_swap (&hmac_ck, client_key_msg, 10);
    sha256_hmac_final (&hmac_ck);

    u32 client_key[16];

    client_key[ 0] = hc_swap32_S (hmac_ck.opad.h[0]);
    client_key[ 1] = hc_swap32_S (hmac_ck.opad.h[1]);
    client_key[ 2] = hc_swap32_S (hmac_ck.opad.h[2]);
    client_key[ 3] = hc_swap32_S (hmac_ck.opad.h[3]);
    client_key[ 4] = hc_swap32_S (hmac_ck.opad.h[4]);
    client_key[ 5] = hc_swap32_S (hmac_ck.opad.h[5]);
    client_key[ 6] = hc_swap32_S (hmac_ck.opad.h[6]);
    client_key[ 7] = hc_swap32_S (hmac_ck.opad.h[7]);
    client_key[ 8] = 0;
    client_key[ 9] = 0;
    client_key[10] = 0;
    client_key[11] = 0;
    client_key[12] = 0;
    client_key[13] = 0;
    client_key[14] = 0;
    client_key[15] = 0;

    sha256_ctx_t sha_sk;

    sha256_init (&sha_sk);
    sha256_update_swap (&sha_sk, client_key, 32);
    sha256_final (&sha_sk);

    dk[0] = hc_swap32_S (sha_sk.h[0]);
    dk[1] = hc_swap32_S (sha_sk.h[1]);
    dk[2] = hc_swap32_S (sha_sk.h[2]);
    dk[3] = hc_swap32_S (sha_sk.h[3]);
    dk[4] = hc_swap32_S (sha_sk.h[4]);
    dk[5] = hc_swap32_S (sha_sk.h[5]);
    dk[6] = hc_swap32_S (sha_sk.h[6]);
    dk[7] = hc_swap32_S (sha_sk.h[7]);
  }
  #endif

  const u32 r0 = dk[0];
  const u32 r1 = dk[1];
  const u32 r2 = dk[2];
  const u32 r3 = dk[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
