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

  u32 pre[PRECOMP_DATALEN]; // 38400 for PRECOMP_BITS = 4

} radmin3_t;

KERNEL_FQ void m29200_mxx (KERN_ATTR_VECTOR_ESALT (radmin3_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);


  /**
   * cache constant values to shared memory
   */

  LOCAL_VK u32 m[64];
  LOCAL_VK u32 r[64];
  LOCAL_VK u32 fact[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    m[i]    = RADMIN3_M[i];
    r[i]    = RADMIN3_R[i];
    fact[i] = RADMIN3_FACT[i];
  }

  SYNC_THREADS ();

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

    sha1_ctx_vector_t c0;

    sha1_init_vector_from_scalar (&c0, &ctx0);

    sha1_update_vector_utf16beN (&c0, w, pw_len);

    sha1_final_vector (&c0);


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

    // u32 r_t[64]; for (u32 i = 0; i < 64; i++) r_t[i] = r[i];

    u32 r_t[64] =
    {
      r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
      r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
      r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
      r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
      r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39],
      r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47],
      r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55],
      r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63],
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

      mul_mod (r_t, pre, m, fact); // r_t = (r_t * RADMIN3_PRE[n]) % m
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

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);


  /**
   * cache constant values to shared memory
   */

  LOCAL_VK u32 m[64];
  LOCAL_VK u32 r[64];
  LOCAL_VK u32 fact[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    m[i]    = RADMIN3_M[i];
    r[i]    = RADMIN3_R[i];
    fact[i] = RADMIN3_FACT[i];
  }

  SYNC_THREADS ();

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

    sha1_ctx_vector_t c0;

    sha1_init_vector_from_scalar (&c0, &ctx0);

    sha1_update_vector_utf16beN (&c0, w, pw_len);

    sha1_final_vector (&c0);


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

    // u32 r_t[64]; for (u32 i = 0; i < 64; i++) r_t[i] = r[i];

    u32 r_t[64] =
    {
      r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
      r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
      r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
      r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
      r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39],
      r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47],
      r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55],
      r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63],
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

      mul_mod (r_t, pre, m, fact); // r_t = (r_t * RADMIN3_PRE[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
