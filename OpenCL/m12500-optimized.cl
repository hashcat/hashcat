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

#define PUTCHAR(a,p,c) ((PRIVATE_AS u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)   ((PRIVATE_AS u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((PRIVATE_AS u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((PRIVATE_AS u8 *)(a))[(p) ^ 3]

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#if defined IS_NV

#define RAR3_COUNTER_0(i,w) hc_byte_perm_S ((i), (w), 0x0124)
#define RAR3_COUNTER_1(i,w) hc_byte_perm_S ((i), (w), 0x7012)
#define RAR3_COUNTER_2(i,w) hc_byte_perm_S ((i), (w), 0x7601)
#define RAR3_COUNTER_3(i,w) hc_byte_perm_S ((i), (w), 0x7650)
#define RAR3_COUNTER_4(i,w) hc_byte_perm_S ((i), (w), 0x1254)

#else

#define RAR3_COUNTER_0(i,w) ((w) | iter_s)
#define RAR3_COUNTER_1(i,w) ((w) | (iter_s >>  8))
#define RAR3_COUNTER_2(i,w) ((w) | (iter_s >> 16))
#define RAR3_COUNTER_3(i,w) ((w) | (iter_s >> 24))
#define RAR3_COUNTER_4(i,w) ((w) | (iter_s <<  8))

#endif

typedef struct rar3_tmp
{
  u32 dgst[17][5];

} rar3_tmp_t;

KERNEL_FQ KERNEL_FA void m12500_init (KERN_ATTR_TMPS (rar3_tmp_t))
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

KERNEL_FQ KERNEL_FA void m12500_loop (KERN_ATTR_TMPS (rar3_tmp_t))
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

  const u32 p2 = pw_len + salt_len;

  const u32 p3 = p2 + 3;

  // Four records end on a word boundary.  Keep just that repeating pattern
  // plus a wrapped prefix, so every 16-word SHA-1 load remains contiguous.

  #define LARGEBLOCK_ELEMS ((40 + 8 + 3) + 15)

  u32 largeblock[LARGEBLOCK_ELEMS];

  // four p3-byte records always end on a u32 boundary

  for (u32 i = 0, p = 0; i < 4; i++)
  {
    for (u32 j = 0; j < pw_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (pw_buf, j));
    }

    for (u32 j = 0; j < salt_len; j++, p += 1)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (salt_buf, j));
    }

    PUTCHAR_BE (largeblock, p + 0, 0);
    PUTCHAR_BE (largeblock, p + 1, 0);
    PUTCHAR_BE (largeblock, p + 2, (LOOP_POS >> 16) & 0xff);

    p += 3;
  }

  // Duplicate enough cyclic words for a contiguous load starting anywhere in
  // the pattern.  p3 can be smaller than 15 for short passwords.

  u32 prefix_pos = 0;

  for (u32 i = 0; i < 15; i++)
  {
    largeblock[p3 + i] = largeblock[prefix_pos];

    prefix_pos++;

    if (prefix_pos == p3) prefix_pos = 0;
  }

  // p3 is in [11, 51].  Using 16 - p3 for the short-record case is
  // equivalent to 16 % p3 and keeps j16 canonical with one subtraction.

  const u32 j_step = (p3 <= 16) ? 16 - p3 : 16;

  const u32 init_pos = LOOP_POS / (ROUNDS / 16);

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[init_pos][0];
  dgst[1] = tmps[gid].dgst[init_pos][1];
  dgst[2] = tmps[gid].dgst[init_pos][2];
  dgst[3] = tmps[gid].dgst[init_pos][3];
  dgst[4] = tmps[gid].dgst[init_pos][4];

  u32 iter = LOOP_POS;

  if (p3 == 16)
  {
    #if !defined IS_NV
    u32 iter_s;
    #endif

    for (u32 block = 0; block < 4096; block++)
    {
      const u32 iter0 = LOOP_POS + (block * 4);

      u32 w[16];

      w[ 0] = largeblock[ 0];
      w[ 1] = largeblock[ 1];
      w[ 2] = largeblock[ 2];
      w[ 3] = largeblock[ 3];
      w[ 4] = largeblock[ 4];
      w[ 5] = largeblock[ 5];
      w[ 6] = largeblock[ 6];
      w[ 7] = largeblock[ 7];
      w[ 8] = largeblock[ 8];
      w[ 9] = largeblock[ 9];
      w[10] = largeblock[10];
      w[11] = largeblock[11];
      w[12] = largeblock[12];
      w[13] = largeblock[13];
      w[14] = largeblock[14];
      w[15] = largeblock[15];

      #if !defined IS_NV
      iter_s = hc_swap32_S (iter0 + 0);
      #endif

      w[ 3] = RAR3_COUNTER_1 (iter0 + 0, w[ 3]);

      #if !defined IS_NV
      iter_s = hc_swap32_S (iter0 + 1);
      #endif

      w[ 7] = RAR3_COUNTER_1 (iter0 + 1, w[ 7]);

      #if !defined IS_NV
      iter_s = hc_swap32_S (iter0 + 2);
      #endif

      w[11] = RAR3_COUNTER_1 (iter0 + 2, w[11]);

      #if !defined IS_NV
      iter_s = hc_swap32_S (iter0 + 3);
      #endif

      w[15] = RAR3_COUNTER_1 (iter0 + 3, w[15]);

      sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);
    }

    tmps[gid].dgst[init_pos + 1][0] = dgst[0];
    tmps[gid].dgst[init_pos + 1][1] = dgst[1];
    tmps[gid].dgst[init_pos + 1][2] = dgst[2];
    tmps[gid].dgst[init_pos + 1][3] = dgst[3];
    tmps[gid].dgst[init_pos + 1][4] = dgst[4];

    return;
  }

  for (u32 i = 0; i < 256; i++)
  {
    u32 tmp = 0;

    u32 k = p2;

    u32 j16 = 0;

    for (u32 j = 0; j < p3; j++)
    {
      u32 w[16];

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

      tmp = 0;

      while (k < 64)
      {
        #if !defined IS_NV

        const u32 iter_s = hc_swap32_S (iter);

        #endif

        switch (k)
        {
          case  0: w[ 0] = RAR3_COUNTER_0 (iter, w[ 0]);
                   break;
          case  1: w[ 0] = RAR3_COUNTER_1 (iter, w[ 0]);
                   break;
          case  2: w[ 0] = RAR3_COUNTER_2 (iter, w[ 0]);
                   break;
          case  3: w[ 0] = RAR3_COUNTER_3 (iter, w[ 0]);
                   w[ 1] = RAR3_COUNTER_4 (iter, w[ 1]);
                   break;
          case  4: w[ 1] = RAR3_COUNTER_0 (iter, w[ 1]);
                   break;
          case  5: w[ 1] = RAR3_COUNTER_1 (iter, w[ 1]);
                   break;
          case  6: w[ 1] = RAR3_COUNTER_2 (iter, w[ 1]);
                   break;
          case  7: w[ 1] = RAR3_COUNTER_3 (iter, w[ 1]);
                   w[ 2] = RAR3_COUNTER_4 (iter, w[ 2]);
                   break;
          case  8: w[ 2] = RAR3_COUNTER_0 (iter, w[ 2]);
                   break;
          case  9: w[ 2] = RAR3_COUNTER_1 (iter, w[ 2]);
                   break;
          case 10: w[ 2] = RAR3_COUNTER_2 (iter, w[ 2]);
                   break;
          case 11: w[ 2] = RAR3_COUNTER_3 (iter, w[ 2]);
                   w[ 3] = RAR3_COUNTER_4 (iter, w[ 3]);
                   break;
          case 12: w[ 3] = RAR3_COUNTER_0 (iter, w[ 3]);
                   break;
          case 13: w[ 3] = RAR3_COUNTER_1 (iter, w[ 3]);
                   break;
          case 14: w[ 3] = RAR3_COUNTER_2 (iter, w[ 3]);
                   break;
          case 15: w[ 3] = RAR3_COUNTER_3 (iter, w[ 3]);
                   w[ 4] = RAR3_COUNTER_4 (iter, w[ 4]);
                   break;
          case 16: w[ 4] = RAR3_COUNTER_0 (iter, w[ 4]);
                   break;
          case 17: w[ 4] = RAR3_COUNTER_1 (iter, w[ 4]);
                   break;
          case 18: w[ 4] = RAR3_COUNTER_2 (iter, w[ 4]);
                   break;
          case 19: w[ 4] = RAR3_COUNTER_3 (iter, w[ 4]);
                   w[ 5] = RAR3_COUNTER_4 (iter, w[ 5]);
                   break;
          case 20: w[ 5] = RAR3_COUNTER_0 (iter, w[ 5]);
                   break;
          case 21: w[ 5] = RAR3_COUNTER_1 (iter, w[ 5]);
                   break;
          case 22: w[ 5] = RAR3_COUNTER_2 (iter, w[ 5]);
                   break;
          case 23: w[ 5] = RAR3_COUNTER_3 (iter, w[ 5]);
                   w[ 6] = RAR3_COUNTER_4 (iter, w[ 6]);
                   break;
          case 24: w[ 6] = RAR3_COUNTER_0 (iter, w[ 6]);
                   break;
          case 25: w[ 6] = RAR3_COUNTER_1 (iter, w[ 6]);
                   break;
          case 26: w[ 6] = RAR3_COUNTER_2 (iter, w[ 6]);
                   break;
          case 27: w[ 6] = RAR3_COUNTER_3 (iter, w[ 6]);
                   w[ 7] = RAR3_COUNTER_4 (iter, w[ 7]);
                   break;
          case 28: w[ 7] = RAR3_COUNTER_0 (iter, w[ 7]);
                   break;
          case 29: w[ 7] = RAR3_COUNTER_1 (iter, w[ 7]);
                   break;
          case 30: w[ 7] = RAR3_COUNTER_2 (iter, w[ 7]);
                   break;
          case 31: w[ 7] = RAR3_COUNTER_3 (iter, w[ 7]);
                   w[ 8] = RAR3_COUNTER_4 (iter, w[ 8]);
                   break;
          case 32: w[ 8] = RAR3_COUNTER_0 (iter, w[ 8]);
                   break;
          case 33: w[ 8] = RAR3_COUNTER_1 (iter, w[ 8]);
                   break;
          case 34: w[ 8] = RAR3_COUNTER_2 (iter, w[ 8]);
                   break;
          case 35: w[ 8] = RAR3_COUNTER_3 (iter, w[ 8]);
                   w[ 9] = RAR3_COUNTER_4 (iter, w[ 9]);
                   break;
          case 36: w[ 9] = RAR3_COUNTER_0 (iter, w[ 9]);
                   break;
          case 37: w[ 9] = RAR3_COUNTER_1 (iter, w[ 9]);
                   break;
          case 38: w[ 9] = RAR3_COUNTER_2 (iter, w[ 9]);
                   break;
          case 39: w[ 9] = RAR3_COUNTER_3 (iter, w[ 9]);
                   w[10] = RAR3_COUNTER_4 (iter, w[10]);
                   break;
          case 40: w[10] = RAR3_COUNTER_0 (iter, w[10]);
                   break;
          case 41: w[10] = RAR3_COUNTER_1 (iter, w[10]);
                   break;
          case 42: w[10] = RAR3_COUNTER_2 (iter, w[10]);
                   break;
          case 43: w[10] = RAR3_COUNTER_3 (iter, w[10]);
                   w[11] = RAR3_COUNTER_4 (iter, w[11]);
                   break;
          case 44: w[11] = RAR3_COUNTER_0 (iter, w[11]);
                   break;
          case 45: w[11] = RAR3_COUNTER_1 (iter, w[11]);
                   break;
          case 46: w[11] = RAR3_COUNTER_2 (iter, w[11]);
                   break;
          case 47: w[11] = RAR3_COUNTER_3 (iter, w[11]);
                   w[12] = RAR3_COUNTER_4 (iter, w[12]);
                   break;
          case 48: w[12] = RAR3_COUNTER_0 (iter, w[12]);
                   break;
          case 49: w[12] = RAR3_COUNTER_1 (iter, w[12]);
                   break;
          case 50: w[12] = RAR3_COUNTER_2 (iter, w[12]);
                   break;
          case 51: w[12] = RAR3_COUNTER_3 (iter, w[12]);
                   w[13] = RAR3_COUNTER_4 (iter, w[13]);
                   break;
          case 52: w[13] = RAR3_COUNTER_0 (iter, w[13]);
                   break;
          case 53: w[13] = RAR3_COUNTER_1 (iter, w[13]);
                   break;
          case 54: w[13] = RAR3_COUNTER_2 (iter, w[13]);
                   break;
          case 55: w[13] = RAR3_COUNTER_3 (iter, w[13]);
                   w[14] = RAR3_COUNTER_4 (iter, w[14]);
                   break;
          case 56: w[14] = RAR3_COUNTER_0 (iter, w[14]);
                   break;
          case 57: w[14] = RAR3_COUNTER_1 (iter, w[14]);
                   break;
          case 58: w[14] = RAR3_COUNTER_2 (iter, w[14]);
                   break;
          case 59: w[14] = RAR3_COUNTER_3 (iter, w[14]);
                   w[15] = RAR3_COUNTER_4 (iter, w[15]);
                   break;
          case 60: w[15] = RAR3_COUNTER_0 (iter, w[15]);
                   break;
          case 61: w[15] = RAR3_COUNTER_1 (iter, w[15]);
                   break;
          case 62: w[15] = RAR3_COUNTER_2 (iter, w[15]);
                   break;
          case 63: w[15] = RAR3_COUNTER_3 (iter, w[15]);
                   tmp   = RAR3_COUNTER_4 (iter, tmp);
                   break;
        }

        iter++;

        k += p3;
      }

      sha1_transform (w + 0, w + 4, w + 8, w + 12, dgst);

      k &= 63;

      j16 += j_step;

      if (j16 >= p3) j16 -= p3;
    }
  }

  tmps[gid].dgst[init_pos + 1][0] = dgst[0];
  tmps[gid].dgst[init_pos + 1][1] = dgst[1];
  tmps[gid].dgst[init_pos + 1][2] = dgst[2];
  tmps[gid].dgst[init_pos + 1][3] = dgst[3];
  tmps[gid].dgst[init_pos + 1][4] = dgst[4];
}

KERNEL_FQ KERNEL_FA void m12500_comp (KERN_ATTR_TMPS (rar3_tmp_t))
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

  u32 dgst[5];

  dgst[0] = tmps[gid].dgst[16][0];
  dgst[1] = tmps[gid].dgst[16][1];
  dgst[2] = tmps[gid].dgst[16][2];
  dgst[3] = tmps[gid].dgst[16][3];
  dgst[4] = tmps[gid].dgst[16][4];

  sha1_transform (w0, w1, w2, w3, dgst);

  u32 ukey[4];

  ukey[0] = hc_swap32_S (dgst[0]);
  ukey[1] = hc_swap32_S (dgst[1]);
  ukey[2] = hc_swap32_S (dgst[2]);
  ukey[3] = hc_swap32_S (dgst[3]);

  u32 ks[44];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 data[4];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  data[2] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  data[3] = salt_bufs[SALT_POS_HOST].salt_buf[5];

  u32 out[4];

  AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

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

  out[0] ^= hc_swap32_S (iv[0]);
  out[1] ^= hc_swap32_S (iv[1]);
  out[2] ^= hc_swap32_S (iv[2]);
  out[3] ^= hc_swap32_S (iv[3]);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
