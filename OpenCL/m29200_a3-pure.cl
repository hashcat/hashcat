/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Further credits:
 * The password-storage algorithm used by Radmin 3 was analyzed and made public
 * by synacktiv:
 * https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_bignum_operations.cl)
#include M2S(INCLUDE_PATH/inc_radmin3_constants.h)
#endif

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN]; // 1047552 * 4 bytes for PRECOMP_BITS = 10

} radmin3_t;

KERNEL_FQ void m29200_mxx (KERN_ATTR_VECTOR_ESALT (radmin3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;


  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }


  // ctx0 with user

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].user, esalt_bufs[DIGESTS_OFFSET_HOST].user_len);


  // ctx1 with main salt

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  sha1_update_global (&ctx1, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  PRIVATE_AS const u32 m[128] =
  {
    RADMIN3_M[  0], RADMIN3_M[  1], RADMIN3_M[  2], RADMIN3_M[  3],
    RADMIN3_M[  4], RADMIN3_M[  5], RADMIN3_M[  6], RADMIN3_M[  7],
    RADMIN3_M[  8], RADMIN3_M[  9], RADMIN3_M[ 10], RADMIN3_M[ 11],
    RADMIN3_M[ 12], RADMIN3_M[ 13], RADMIN3_M[ 14], RADMIN3_M[ 15],
    RADMIN3_M[ 16], RADMIN3_M[ 17], RADMIN3_M[ 18], RADMIN3_M[ 19],
    RADMIN3_M[ 20], RADMIN3_M[ 21], RADMIN3_M[ 22], RADMIN3_M[ 23],
    RADMIN3_M[ 24], RADMIN3_M[ 25], RADMIN3_M[ 26], RADMIN3_M[ 27],
    RADMIN3_M[ 28], RADMIN3_M[ 29], RADMIN3_M[ 30], RADMIN3_M[ 31],
    RADMIN3_M[ 32], RADMIN3_M[ 33], RADMIN3_M[ 34], RADMIN3_M[ 35],
    RADMIN3_M[ 36], RADMIN3_M[ 37], RADMIN3_M[ 38], RADMIN3_M[ 39],
    RADMIN3_M[ 40], RADMIN3_M[ 41], RADMIN3_M[ 42], RADMIN3_M[ 43],
    RADMIN3_M[ 44], RADMIN3_M[ 45], RADMIN3_M[ 46], RADMIN3_M[ 47],
    RADMIN3_M[ 48], RADMIN3_M[ 49], RADMIN3_M[ 50], RADMIN3_M[ 51],
    RADMIN3_M[ 52], RADMIN3_M[ 53], RADMIN3_M[ 54], RADMIN3_M[ 55],
    RADMIN3_M[ 56], RADMIN3_M[ 57], RADMIN3_M[ 58], RADMIN3_M[ 59],
    RADMIN3_M[ 60], RADMIN3_M[ 61], RADMIN3_M[ 62], RADMIN3_M[ 63],
    RADMIN3_M[ 64], RADMIN3_M[ 65], RADMIN3_M[ 66], RADMIN3_M[ 67],
    RADMIN3_M[ 68], RADMIN3_M[ 69], RADMIN3_M[ 70], RADMIN3_M[ 71],
    RADMIN3_M[ 72], RADMIN3_M[ 73], RADMIN3_M[ 74], RADMIN3_M[ 75],
    RADMIN3_M[ 76], RADMIN3_M[ 77], RADMIN3_M[ 78], RADMIN3_M[ 79],
    RADMIN3_M[ 80], RADMIN3_M[ 81], RADMIN3_M[ 82], RADMIN3_M[ 83],
    RADMIN3_M[ 84], RADMIN3_M[ 85], RADMIN3_M[ 86], RADMIN3_M[ 87],
    RADMIN3_M[ 88], RADMIN3_M[ 89], RADMIN3_M[ 90], RADMIN3_M[ 91],
    RADMIN3_M[ 92], RADMIN3_M[ 93], RADMIN3_M[ 94], RADMIN3_M[ 95],
    RADMIN3_M[ 96], RADMIN3_M[ 97], RADMIN3_M[ 98], RADMIN3_M[ 99],
    RADMIN3_M[100], RADMIN3_M[101], RADMIN3_M[102], RADMIN3_M[103],
    RADMIN3_M[104], RADMIN3_M[105], RADMIN3_M[106], RADMIN3_M[107],
    RADMIN3_M[108], RADMIN3_M[109], RADMIN3_M[110], RADMIN3_M[111],
    RADMIN3_M[112], RADMIN3_M[113], RADMIN3_M[114], RADMIN3_M[115],
    RADMIN3_M[116], RADMIN3_M[117], RADMIN3_M[118], RADMIN3_M[119],
    RADMIN3_M[120], RADMIN3_M[121], RADMIN3_M[122], RADMIN3_M[123],
    RADMIN3_M[124], RADMIN3_M[125], RADMIN3_M[126], RADMIN3_M[127],
  };

  PRIVATE_AS const u32 fact[64] =
  {
    RADMIN3_FACT[ 0], RADMIN3_FACT[ 1], RADMIN3_FACT[ 2], RADMIN3_FACT[ 3],
    RADMIN3_FACT[ 4], RADMIN3_FACT[ 5], RADMIN3_FACT[ 6], RADMIN3_FACT[ 7],
    RADMIN3_FACT[ 8], RADMIN3_FACT[ 9], RADMIN3_FACT[10], RADMIN3_FACT[11],
    RADMIN3_FACT[12], RADMIN3_FACT[13], RADMIN3_FACT[14], RADMIN3_FACT[15],
    RADMIN3_FACT[16], RADMIN3_FACT[17], RADMIN3_FACT[18], RADMIN3_FACT[19],
    RADMIN3_FACT[20], RADMIN3_FACT[21], RADMIN3_FACT[22], RADMIN3_FACT[23],
    RADMIN3_FACT[24], RADMIN3_FACT[25], RADMIN3_FACT[26], RADMIN3_FACT[27],
    RADMIN3_FACT[28], RADMIN3_FACT[29], RADMIN3_FACT[30], RADMIN3_FACT[31],
    RADMIN3_FACT[32], RADMIN3_FACT[33], RADMIN3_FACT[34], RADMIN3_FACT[35],
    RADMIN3_FACT[36], RADMIN3_FACT[37], RADMIN3_FACT[38], RADMIN3_FACT[39],
    RADMIN3_FACT[40], RADMIN3_FACT[41], RADMIN3_FACT[42], RADMIN3_FACT[43],
    RADMIN3_FACT[44], RADMIN3_FACT[45], RADMIN3_FACT[46], RADMIN3_FACT[47],
    RADMIN3_FACT[48], RADMIN3_FACT[49], RADMIN3_FACT[50], RADMIN3_FACT[51],
    RADMIN3_FACT[52], RADMIN3_FACT[53], RADMIN3_FACT[54], RADMIN3_FACT[55],
    RADMIN3_FACT[56], RADMIN3_FACT[57], RADMIN3_FACT[58], RADMIN3_FACT[59],
    RADMIN3_FACT[60], RADMIN3_FACT[61], RADMIN3_FACT[62], RADMIN3_FACT[63],
  };


  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;


    // add password to the user name (and colon, included):

    sha1_ctx_t c0 = ctx0;

    sha1_update_utf16beN (&c0, w, pw_len);

    sha1_final (&c0);


    // add first SHA1 result to main salt:

    sha1_ctx_t c1 = ctx1;

    u32 w0_t[4] = { 0 };
    u32 w1_t[4] = { 0 };
    u32 w2_t[4] = { 0 };
    u32 w3_t[4] = { 0 };

    w0_t[0] = c0.h[0];
    w0_t[1] = c0.h[1];
    w0_t[2] = c0.h[2];
    w0_t[3] = c0.h[3];
    w1_t[0] = c0.h[4];

    sha1_update_64 (&c1, w0_t, w1_t, w2_t, w3_t, 20);

    sha1_final (&c1);

    const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

    u32 r_t[64] =
    {
      RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
      RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
      RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
      RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
      RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
      RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
      RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
      RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
      RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
      RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
      RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
      RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
      RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
      RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
      RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
      RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
    };


    // main loop over the SHA1 result/vector e[]:

    for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
    {
      const u32 div   = (PRECOMP_BITS * i) / 32; // for 4 bits: (i / 8)
      const u32 shift = (PRECOMP_BITS * i) % 32; // for 4 bits: (i % 8) * 4

      // const
      u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK; // 0x0f == 0b1111 (4 bits)

      // working with non-divisible u32 (see PRECOMP_BITS):

      if (32 - shift < PRECOMP_BITS)
      {
        cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
      }

      if (cur_sel == 0) continue;

      const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN; // x * 64 is same as x << 6

      // u32 pre[64]; for (u32 i = 0; i < 64; i++) pre[i] = esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + i];

      const u32 pre[64] =
      {
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  0],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  1],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  2],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  3],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  4],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  5],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  6],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  7],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  8],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  9],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 10],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 11],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 12],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 13],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 14],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 15],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 16],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 17],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 18],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 19],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 20],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 21],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 22],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 23],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 24],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 25],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 26],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 27],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 28],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 29],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 30],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 31],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 32],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 33],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 34],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 35],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 36],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 37],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 38],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 39],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 40],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 41],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 42],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 43],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 44],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 45],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 46],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 47],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 48],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 49],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 50],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 51],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 52],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 53],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 54],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 55],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 56],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 57],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 58],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 59],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 60],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 61],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 62],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 63],
      };

      mul_mod128 (r_t, pre, m, fact); // r_t = (r_t * RADMIN3_PRE[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m29200_sxx (KERN_ATTR_VECTOR_ESALT (radmin3_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;


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
   * base
   */


  // ctx0 with user

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].user, esalt_bufs[DIGESTS_OFFSET_HOST].user_len);


  // ctx1 with main salt

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  sha1_update_global (&ctx1, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);


  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  PRIVATE_AS const u32 m[128] =
  {
    RADMIN3_M[  0], RADMIN3_M[  1], RADMIN3_M[  2], RADMIN3_M[  3],
    RADMIN3_M[  4], RADMIN3_M[  5], RADMIN3_M[  6], RADMIN3_M[  7],
    RADMIN3_M[  8], RADMIN3_M[  9], RADMIN3_M[ 10], RADMIN3_M[ 11],
    RADMIN3_M[ 12], RADMIN3_M[ 13], RADMIN3_M[ 14], RADMIN3_M[ 15],
    RADMIN3_M[ 16], RADMIN3_M[ 17], RADMIN3_M[ 18], RADMIN3_M[ 19],
    RADMIN3_M[ 20], RADMIN3_M[ 21], RADMIN3_M[ 22], RADMIN3_M[ 23],
    RADMIN3_M[ 24], RADMIN3_M[ 25], RADMIN3_M[ 26], RADMIN3_M[ 27],
    RADMIN3_M[ 28], RADMIN3_M[ 29], RADMIN3_M[ 30], RADMIN3_M[ 31],
    RADMIN3_M[ 32], RADMIN3_M[ 33], RADMIN3_M[ 34], RADMIN3_M[ 35],
    RADMIN3_M[ 36], RADMIN3_M[ 37], RADMIN3_M[ 38], RADMIN3_M[ 39],
    RADMIN3_M[ 40], RADMIN3_M[ 41], RADMIN3_M[ 42], RADMIN3_M[ 43],
    RADMIN3_M[ 44], RADMIN3_M[ 45], RADMIN3_M[ 46], RADMIN3_M[ 47],
    RADMIN3_M[ 48], RADMIN3_M[ 49], RADMIN3_M[ 50], RADMIN3_M[ 51],
    RADMIN3_M[ 52], RADMIN3_M[ 53], RADMIN3_M[ 54], RADMIN3_M[ 55],
    RADMIN3_M[ 56], RADMIN3_M[ 57], RADMIN3_M[ 58], RADMIN3_M[ 59],
    RADMIN3_M[ 60], RADMIN3_M[ 61], RADMIN3_M[ 62], RADMIN3_M[ 63],
    RADMIN3_M[ 64], RADMIN3_M[ 65], RADMIN3_M[ 66], RADMIN3_M[ 67],
    RADMIN3_M[ 68], RADMIN3_M[ 69], RADMIN3_M[ 70], RADMIN3_M[ 71],
    RADMIN3_M[ 72], RADMIN3_M[ 73], RADMIN3_M[ 74], RADMIN3_M[ 75],
    RADMIN3_M[ 76], RADMIN3_M[ 77], RADMIN3_M[ 78], RADMIN3_M[ 79],
    RADMIN3_M[ 80], RADMIN3_M[ 81], RADMIN3_M[ 82], RADMIN3_M[ 83],
    RADMIN3_M[ 84], RADMIN3_M[ 85], RADMIN3_M[ 86], RADMIN3_M[ 87],
    RADMIN3_M[ 88], RADMIN3_M[ 89], RADMIN3_M[ 90], RADMIN3_M[ 91],
    RADMIN3_M[ 92], RADMIN3_M[ 93], RADMIN3_M[ 94], RADMIN3_M[ 95],
    RADMIN3_M[ 96], RADMIN3_M[ 97], RADMIN3_M[ 98], RADMIN3_M[ 99],
    RADMIN3_M[100], RADMIN3_M[101], RADMIN3_M[102], RADMIN3_M[103],
    RADMIN3_M[104], RADMIN3_M[105], RADMIN3_M[106], RADMIN3_M[107],
    RADMIN3_M[108], RADMIN3_M[109], RADMIN3_M[110], RADMIN3_M[111],
    RADMIN3_M[112], RADMIN3_M[113], RADMIN3_M[114], RADMIN3_M[115],
    RADMIN3_M[116], RADMIN3_M[117], RADMIN3_M[118], RADMIN3_M[119],
    RADMIN3_M[120], RADMIN3_M[121], RADMIN3_M[122], RADMIN3_M[123],
    RADMIN3_M[124], RADMIN3_M[125], RADMIN3_M[126], RADMIN3_M[127],
  };

  PRIVATE_AS const u32 fact[64] =
  {
    RADMIN3_FACT[ 0], RADMIN3_FACT[ 1], RADMIN3_FACT[ 2], RADMIN3_FACT[ 3],
    RADMIN3_FACT[ 4], RADMIN3_FACT[ 5], RADMIN3_FACT[ 6], RADMIN3_FACT[ 7],
    RADMIN3_FACT[ 8], RADMIN3_FACT[ 9], RADMIN3_FACT[10], RADMIN3_FACT[11],
    RADMIN3_FACT[12], RADMIN3_FACT[13], RADMIN3_FACT[14], RADMIN3_FACT[15],
    RADMIN3_FACT[16], RADMIN3_FACT[17], RADMIN3_FACT[18], RADMIN3_FACT[19],
    RADMIN3_FACT[20], RADMIN3_FACT[21], RADMIN3_FACT[22], RADMIN3_FACT[23],
    RADMIN3_FACT[24], RADMIN3_FACT[25], RADMIN3_FACT[26], RADMIN3_FACT[27],
    RADMIN3_FACT[28], RADMIN3_FACT[29], RADMIN3_FACT[30], RADMIN3_FACT[31],
    RADMIN3_FACT[32], RADMIN3_FACT[33], RADMIN3_FACT[34], RADMIN3_FACT[35],
    RADMIN3_FACT[36], RADMIN3_FACT[37], RADMIN3_FACT[38], RADMIN3_FACT[39],
    RADMIN3_FACT[40], RADMIN3_FACT[41], RADMIN3_FACT[42], RADMIN3_FACT[43],
    RADMIN3_FACT[44], RADMIN3_FACT[45], RADMIN3_FACT[46], RADMIN3_FACT[47],
    RADMIN3_FACT[48], RADMIN3_FACT[49], RADMIN3_FACT[50], RADMIN3_FACT[51],
    RADMIN3_FACT[52], RADMIN3_FACT[53], RADMIN3_FACT[54], RADMIN3_FACT[55],
    RADMIN3_FACT[56], RADMIN3_FACT[57], RADMIN3_FACT[58], RADMIN3_FACT[59],
    RADMIN3_FACT[60], RADMIN3_FACT[61], RADMIN3_FACT[62], RADMIN3_FACT[63],
  };


  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;


    // add password to the user name (and colon, included):

    sha1_ctx_t c0 = ctx0;

    sha1_update_utf16beN (&c0, w, pw_len);

    sha1_final (&c0);


    // add first SHA1 result to main salt:

    sha1_ctx_t c1 = ctx1;

    u32 w0_t[4] = { 0 };
    u32 w1_t[4] = { 0 };
    u32 w2_t[4] = { 0 };
    u32 w3_t[4] = { 0 };

    w0_t[0] = c0.h[0];
    w0_t[1] = c0.h[1];
    w0_t[2] = c0.h[2];
    w0_t[3] = c0.h[3];
    w1_t[0] = c0.h[4];

    sha1_update_64 (&c1, w0_t, w1_t, w2_t, w3_t, 20);

    sha1_final (&c1);

    const u32 e[5] = { c1.h[4], c1.h[3], c1.h[2], c1.h[1], c1.h[0] };

    u32 r_t[64] =
    {
      RADMIN3_R[ 0], RADMIN3_R[ 1], RADMIN3_R[ 2], RADMIN3_R[ 3],
      RADMIN3_R[ 4], RADMIN3_R[ 5], RADMIN3_R[ 6], RADMIN3_R[ 7],
      RADMIN3_R[ 8], RADMIN3_R[ 9], RADMIN3_R[10], RADMIN3_R[11],
      RADMIN3_R[12], RADMIN3_R[13], RADMIN3_R[14], RADMIN3_R[15],
      RADMIN3_R[16], RADMIN3_R[17], RADMIN3_R[18], RADMIN3_R[19],
      RADMIN3_R[20], RADMIN3_R[21], RADMIN3_R[22], RADMIN3_R[23],
      RADMIN3_R[24], RADMIN3_R[25], RADMIN3_R[26], RADMIN3_R[27],
      RADMIN3_R[28], RADMIN3_R[29], RADMIN3_R[30], RADMIN3_R[31],
      RADMIN3_R[32], RADMIN3_R[33], RADMIN3_R[34], RADMIN3_R[35],
      RADMIN3_R[36], RADMIN3_R[37], RADMIN3_R[38], RADMIN3_R[39],
      RADMIN3_R[40], RADMIN3_R[41], RADMIN3_R[42], RADMIN3_R[43],
      RADMIN3_R[44], RADMIN3_R[45], RADMIN3_R[46], RADMIN3_R[47],
      RADMIN3_R[48], RADMIN3_R[49], RADMIN3_R[50], RADMIN3_R[51],
      RADMIN3_R[52], RADMIN3_R[53], RADMIN3_R[54], RADMIN3_R[55],
      RADMIN3_R[56], RADMIN3_R[57], RADMIN3_R[58], RADMIN3_R[59],
      RADMIN3_R[60], RADMIN3_R[61], RADMIN3_R[62], RADMIN3_R[63],
    };


    // main loop over the SHA1 result/vector e[]:

    for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
    {
      const u32 div   = (PRECOMP_BITS * i) / 32; // for 4 bits: (i / 8)
      const u32 shift = (PRECOMP_BITS * i) % 32; // for 4 bits: (i % 8) * 4

      // const
      u32 cur_sel = (e[div] >> shift) & PRECOMP_MASK; // 0x0f == 0b1111 (4 bits)

      // working with non-divisible u32 (see PRECOMP_BITS):

      if (32 - shift < PRECOMP_BITS)
      {
        cur_sel |= (e[div + 1] << (32 - shift)) & PRECOMP_MASK;
      }

      if (cur_sel == 0) continue;

      const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN; // x * 64 is same as x << 6

      // u32 pre[64]; for (u32 i = 0; i < 64; i++) pre[i] = esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + i];

      const u32 pre[64] =
      {
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  0],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  1],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  2],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  3],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  4],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  5],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  6],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  7],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  8],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  9],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 10],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 11],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 12],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 13],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 14],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 15],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 16],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 17],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 18],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 19],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 20],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 21],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 22],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 23],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 24],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 25],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 26],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 27],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 28],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 29],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 30],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 31],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 32],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 33],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 34],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 35],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 36],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 37],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 38],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 39],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 40],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 41],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 42],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 43],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 44],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 45],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 46],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 47],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 48],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 49],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 50],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 51],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 52],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 53],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 54],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 55],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 56],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 57],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 58],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 59],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 60],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 61],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 62],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 63],
      };

      mul_mod128 (r_t, pre, m, fact); // r_t = (r_t * RADMIN3_PRE[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
