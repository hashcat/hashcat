/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define ROUNDS 0x40000

#define PUTCHAR(a,p,c)    ((PRIVATE_AS u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)      ((PRIVATE_AS u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((PRIVATE_AS u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((PRIVATE_AS u8 *)(a))[(p) ^ 3]

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

typedef struct rar3
{
  u32 first_block_encrypted[4];

} rar3_t;

typedef struct rar3_tmp
{
  u32 dgst[17][5];

} rar3_tmp_t;

typedef struct rar3_hook
{
  u32 key[4];
  u32 iv[4];

  u32 first_block_decrypted[4];

  u32 crc32;

} rar3_hook_t;

KERNEL_FQ void m23800_init (KERN_ATTR_TMPS_HOOKS_ESALT (rar3_tmp_t, rar3_hook_t, rar3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].dgst[0][0] = SHA1M_A;
  tmps[gid].dgst[0][1] = SHA1M_B;
  tmps[gid].dgst[0][2] = SHA1M_C;
  tmps[gid].dgst[0][3] = SHA1M_D;
  tmps[gid].dgst[0][4] = SHA1M_E;
}

KERNEL_FQ void m23800_loop (KERN_ATTR_TMPS_HOOKS_ESALT (rar3_tmp_t, rar3_hook_t, rar3_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf[10];

  pw_buf[0] = pws[gid].i[0];
  pw_buf[1] = pws[gid].i[1];
  pw_buf[2] = pws[gid].i[2];
  pw_buf[3] = pws[gid].i[3];
  pw_buf[4] = pws[gid].i[4];
  pw_buf[5] = pws[gid].i[5];
  pw_buf[6] = pws[gid].i[6];
  pw_buf[7] = pws[gid].i[7];
  pw_buf[8] = pws[gid].i[8];
  pw_buf[9] = pws[gid].i[9];

  const u32 pw_len = MIN (pws[gid].pw_len, 40);

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 salt_len = 8;

  // this is large enough to hold all possible w[] arrays for 64 iterations

  #define LARGEBLOCK_ELEMS ((40 + 8 + 3) * 16)

  u32 largeblock[LARGEBLOCK_ELEMS];

  for (u32 i = 0; i < LARGEBLOCK_ELEMS; i++) largeblock[i] = 0;

  for (u32 i = 0, p = 0; i < 64; i++)
  {
    for (u32 j = 0; j < pw_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (salt_buf, j));
    }

    PUTCHAR_BE (largeblock, p + 2, (LOOP_POS >> 16) & 0xff);

    p += 3;
  }

  const u32 p2 = pw_len + salt_len;

  const u32 p3 = pw_len + salt_len + 3;

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[init_pos][0];
  dgst[1] = tmps[gid].dgst[init_pos][1];
  dgst[2] = tmps[gid].dgst[init_pos][2];
  dgst[3] = tmps[gid].dgst[init_pos][3];
  dgst[4] = tmps[gid].dgst[init_pos][4];

  u32 iter = LOOP_POS;

  for (u32 i = 0; i < 256; i++)
  {
    u32 tmp = 0;

    u32 k = p2;

    for (u32 j = 0; j < p3; j++)
    {
      const u32 j16 = j * 16;

      u32 w[16 + 1];

      w[ 0] = largeblock[j16 +  0] | tmp;
      w[ 1] = largeblock[j16 +  1];
      w[ 2] = largeblock[j16 +  2];
      w[ 3] = largeblock[j16 +  3];
      w[ 4] = largeblock[j16 +  4];
      w[ 5] = largeblock[j16 +  5];
      w[ 6] = largeblock[j16 +  6];
      w[ 7] = largeblock[j16 +  7];
      w[ 8] = largeblock[j16 +  8];
      w[ 9] = largeblock[j16 +  9];
      w[10] = largeblock[j16 + 10];
      w[11] = largeblock[j16 + 11];
      w[12] = largeblock[j16 + 12];
      w[13] = largeblock[j16 + 13];
      w[14] = largeblock[j16 + 14];
      w[15] = largeblock[j16 + 15];
      w[16] = 0;

      while (k < 64)
      {
        const u32 iter_s = hc_swap32_S (iter);

        u32 mask0 = 0;
        u32 mask1 = 0;

        u32 tmp0 = 0;
        u32 tmp1 = 0;

        const int kd = k / 4;
        const int km = k & 3;

             if (km == 0) { tmp0 = iter_s >>  0; tmp1 = 0;            mask0 = 0x0000ffff; mask1 = 0xffffffff; }
        else if (km == 1) { tmp0 = iter_s >>  8; tmp1 = 0;            mask0 = 0xff0000ff; mask1 = 0xffffffff; }
        else if (km == 2) { tmp0 = iter_s >> 16; tmp1 = 0;            mask0 = 0xffff0000; mask1 = 0xffffffff; }
        else if (km == 3) { tmp0 = iter_s >> 24; tmp1 = iter_s <<  8; mask0 = 0xffffff00; mask1 = 0x00ffffff; }

        switch (kd)
        {
          case  0: w[ 0] = (w[ 0] & mask0) | tmp0;
                   w[ 1] = (w[ 1] & mask1) | tmp1;
                   break;
          case  1: w[ 1] = (w[ 1] & mask0) | tmp0;
                   w[ 2] = (w[ 2] & mask1) | tmp1;
                   break;
          case  2: w[ 2] = (w[ 2] & mask0) | tmp0;
                   w[ 3] = (w[ 3] & mask1) | tmp1;
                   break;
          case  3: w[ 3] = (w[ 3] & mask0) | tmp0;
                   w[ 4] = (w[ 4] & mask1) | tmp1;
                   break;
          case  4: w[ 4] = (w[ 4] & mask0) | tmp0;
                   w[ 5] = (w[ 5] & mask1) | tmp1;
                   break;
          case  5: w[ 5] = (w[ 5] & mask0) | tmp0;
                   w[ 6] = (w[ 6] & mask1) | tmp1;
                   break;
          case  6: w[ 6] = (w[ 6] & mask0) | tmp0;
                   w[ 7] = (w[ 7] & mask1) | tmp1;
                   break;
          case  7: w[ 7] = (w[ 7] & mask0) | tmp0;
                   w[ 8] = (w[ 8] & mask1) | tmp1;
                   break;
          case  8: w[ 8] = (w[ 8] & mask0) | tmp0;
                   w[ 9] = (w[ 9] & mask1) | tmp1;
                   break;
          case  9: w[ 9] = (w[ 9] & mask0) | tmp0;
                   w[10] = (w[10] & mask1) | tmp1;
                   break;
          case 10: w[10] = (w[10] & mask0) | tmp0;
                   w[11] = (w[11] & mask1) | tmp1;
                   break;
          case 11: w[11] = (w[11] & mask0) | tmp0;
                   w[12] = (w[12] & mask1) | tmp1;
                   break;
          case 12: w[12] = (w[12] & mask0) | tmp0;
                   w[13] = (w[13] & mask1) | tmp1;
                   break;
          case 13: w[13] = (w[13] & mask0) | tmp0;
                   w[14] = (w[14] & mask1) | tmp1;
                   break;
          case 14: w[14] = (w[14] & mask0) | tmp0;
                   w[15] = (w[15] & mask1) | tmp1;
                   break;
          case 15: w[15] = (w[15] & mask0) | tmp0;
                   w[16] =                   tmp1;
                   break;
        }

        iter++;

        k += p3;
      }

      sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);

      k &= 63;

      tmp = w[16];
    }
  }

  tmps[gid].dgst[init_pos + 1][0] = dgst[0];
  tmps[gid].dgst[init_pos + 1][1] = dgst[1];
  tmps[gid].dgst[init_pos + 1][2] = dgst[2];
  tmps[gid].dgst[init_pos + 1][3] = dgst[3];
  tmps[gid].dgst[init_pos + 1][4] = dgst[4];
}

KERNEL_FQ void m23800_hook23 (KERN_ATTR_TMPS_HOOKS_ESALT (rar3_tmp_t, rar3_hook_t, rar3_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
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

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = MIN (pws[gid].pw_len, 40);

  const u32 salt_len = 8;

  const u32 p3 = pw_len + salt_len + 3;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 0x80000000;
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
  w3[3] = (p3 * ROUNDS) * 8;

  u32 h[5];

  h[0] = tmps[gid].dgst[16][0];
  h[1] = tmps[gid].dgst[16][1];
  h[2] = tmps[gid].dgst[16][2];
  h[3] = tmps[gid].dgst[16][3];
  h[4] = tmps[gid].dgst[16][4];

  sha1_transform (w0, w1, w2, w3, h);

  u32 iv[4];

  iv[0] = 0;
  iv[1] = 0;
  iv[2] = 0;
  iv[3] = 0;

  for (int i = 0; i < 16; i++)
  {
    u32 pw_buf[10];

    pw_buf[0] = pws[gid].i[0];
    pw_buf[1] = pws[gid].i[1];
    pw_buf[2] = pws[gid].i[2];
    pw_buf[3] = pws[gid].i[3];
    pw_buf[4] = pws[gid].i[4];
    pw_buf[5] = pws[gid].i[5];
    pw_buf[6] = pws[gid].i[6];
    pw_buf[7] = pws[gid].i[7];
    pw_buf[8] = pws[gid].i[8];
    pw_buf[9] = pws[gid].i[9];

    //const u32 pw_len = pws[gid].pw_len;

    u32 salt_buf[2];

    salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
    salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

    //const u32 salt_len = 8;

    //const u32 p3 = pw_len + salt_len + 3;

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

    for (u32 j = 0; j < pw_len; j++, p += 1)
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

    sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);

    PUTCHAR (iv, i, dgst[4] & 0xff);
  }

  hooks[gid].key[0] = h[0];
  hooks[gid].key[1] = h[1];
  hooks[gid].key[2] = h[2];
  hooks[gid].key[3] = h[3];

  hooks[gid].iv[0] = iv[0];
  hooks[gid].iv[1] = iv[1];
  hooks[gid].iv[2] = iv[2];
  hooks[gid].iv[3] = iv[3];

  u32 ukey[4];

  ukey[0] = hc_swap32_S (h[0]);
  ukey[1] = hc_swap32_S (h[1]);
  ukey[2] = hc_swap32_S (h[2]);
  ukey[3] = hc_swap32_S (h[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 data[4];

  data[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].first_block_encrypted[0]);
  data[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].first_block_encrypted[1]);
  data[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].first_block_encrypted[2]);
  data[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].first_block_encrypted[3]);

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= hc_swap32_S (iv[0]);
  out[1] ^= hc_swap32_S (iv[1]);
  out[2] ^= hc_swap32_S (iv[2]);
  out[3] ^= hc_swap32_S (iv[3]);

  hooks[gid].first_block_decrypted[0] = hc_swap32_S (out[0]);
  hooks[gid].first_block_decrypted[1] = hc_swap32_S (out[1]);
  hooks[gid].first_block_decrypted[2] = hc_swap32_S (out[2]);
  hooks[gid].first_block_decrypted[3] = hc_swap32_S (out[3]);
}

KERNEL_FQ void m23800_comp (KERN_ATTR_TMPS_HOOKS_ESALT (rar3_tmp_t, rar3_hook_t, rar3_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 crc32 = hooks[gid].crc32;

  const u32 r0 = crc32;
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
