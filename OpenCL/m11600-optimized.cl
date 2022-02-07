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
#endif

typedef struct seven_zip_tmp
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} seven_zip_tmp_t;

typedef struct
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

#define PUTCHAR(a,p,c) ((PRIVATE_AS u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR(a,p)   ((PRIVATE_AS u8 *)(a))[(p)]

#define PUTCHAR_BE(a,p,c) ((PRIVATE_AS u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR_BE(a,p)   ((PRIVATE_AS u8 *)(a))[(p) ^ 3]

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

KERNEL_FQ void m11600_init (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  tmps[gid].h[0] = SHA256M_A;
  tmps[gid].h[1] = SHA256M_B;
  tmps[gid].h[2] = SHA256M_C;
  tmps[gid].h[3] = SHA256M_D;
  tmps[gid].h[4] = SHA256M_E;
  tmps[gid].h[5] = SHA256M_F;
  tmps[gid].h[6] = SHA256M_G;
  tmps[gid].h[7] = SHA256M_H;

  tmps[gid].len = 0;
}

KERNEL_FQ void m11600_loop (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf[5];

  pw_buf[0] = pws[gid].i[0];
  pw_buf[1] = pws[gid].i[1];
  pw_buf[2] = pws[gid].i[2];
  pw_buf[3] = pws[gid].i[3];
  pw_buf[4] = pws[gid].i[4];

  const u32 pw_len = MIN (pws[gid].pw_len, 20);

  // this is large enough to hold all possible w[] arrays for 64 iterations

  #define LARGEBLOCK_ELEMS ((40 + 8) * 16)

  u32 largeblock[LARGEBLOCK_ELEMS];

  PRIVATE_AS u8 *ptr = (PRIVATE_AS u8 *) largeblock;

  for (u32 i = 0; i < LARGEBLOCK_ELEMS; i++) largeblock[i] = 0;

  u32 loop_pos_pos = LOOP_POS;

  for (u32 i = 0, p = 0; i < 64; i++)
  {
    for (u32 j = 0; j < pw_len; j++, p += 2)
    {
      PUTCHAR_BE (largeblock, p, GETCHAR (pw_buf, j));
    }

    const u8 byte2 = unpack_v8c_from_v32_S (loop_pos_pos);
    const u8 byte3 = unpack_v8d_from_v32_S (loop_pos_pos);

    PUTCHAR_BE (largeblock, p + 2, byte2);
    PUTCHAR_BE (largeblock, p + 3, byte3);

    loop_pos_pos++;

    p += 8;
  }

  u32 h[8];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];
  h[5] = tmps[gid].h[5];
  h[6] = tmps[gid].h[6];
  h[7] = tmps[gid].h[7];

  const int iter64 = (pw_len * 2) + 8;

  loop_pos_pos = LOOP_POS;

  for (u32 i = 0; i < LOOP_CNT; i += 64)
  {
    // iteration set
    for (u32 i = 0, p = pw_len * 2; i < 64; i++, p += iter64)
    {
      const u8 byte0 = unpack_v8a_from_v32_S (loop_pos_pos);
      const u8 byte1 = unpack_v8b_from_v32_S (loop_pos_pos);

      PUTCHAR_BE (largeblock, p + 0, byte0);
      PUTCHAR_BE (largeblock, p + 1, byte1);

      loop_pos_pos++;
    }

    // full 64 byte buffer
    for (int j = 0, j16 = 0; j < iter64; j++, j16 += 16)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = largeblock[j16 +  0];
      w0[1] = largeblock[j16 +  1];
      w0[2] = largeblock[j16 +  2];
      w0[3] = largeblock[j16 +  3];
      w1[0] = largeblock[j16 +  4];
      w1[1] = largeblock[j16 +  5];
      w1[2] = largeblock[j16 +  6];
      w1[3] = largeblock[j16 +  7];
      w2[0] = largeblock[j16 +  8];
      w2[1] = largeblock[j16 +  9];
      w2[2] = largeblock[j16 + 10];
      w2[3] = largeblock[j16 + 11];
      w3[0] = largeblock[j16 + 12];
      w3[1] = largeblock[j16 + 13];
      w3[2] = largeblock[j16 + 14];
      w3[3] = largeblock[j16 + 15];

      sha256_transform (w0, w1, w2, w3, h);
    }
  }

  tmps[gid].len += LOOP_CNT * iter64;

  tmps[gid].h[0] = h[0];
  tmps[gid].h[1] = h[1];
  tmps[gid].h[2] = h[2];
  tmps[gid].h[3] = h[3];
  tmps[gid].h[4] = h[4];
  tmps[gid].h[5] = h[5];
  tmps[gid].h[6] = h[6];
  tmps[gid].h[7] = h[7];
}

KERNEL_FQ void m11600_hook23 (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * context load
   */

  u32 h[8];

  h[0] = tmps[gid].h[0];
  h[1] = tmps[gid].h[1];
  h[2] = tmps[gid].h[2];
  h[3] = tmps[gid].h[3];
  h[4] = tmps[gid].h[4];
  h[5] = tmps[gid].h[5];
  h[6] = tmps[gid].h[6];
  h[7] = tmps[gid].h[7];

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
  w3[3] = tmps[gid].len * 8;

  sha256_transform (w0, w1, w2, w3, h);

  hooks[gid].ukey[0] = hc_swap32_S (h[0]);
  hooks[gid].ukey[1] = hc_swap32_S (h[1]);
  hooks[gid].ukey[2] = hc_swap32_S (h[2]);
  hooks[gid].ukey[3] = hc_swap32_S (h[3]);
  hooks[gid].ukey[4] = hc_swap32_S (h[4]);
  hooks[gid].ukey[5] = hc_swap32_S (h[5]);
  hooks[gid].ukey[6] = hc_swap32_S (h[6]);
  hooks[gid].ukey[7] = hc_swap32_S (h[7]);
}

KERNEL_FQ void m11600_comp (KERN_ATTR_TMPS_HOOKS (seven_zip_tmp_t, seven_zip_hook_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (hooks[gid].hook_success == 1)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
