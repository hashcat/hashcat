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
#include M2S(INCLUDE_PATH/inc_bignum_2048.cl)
#include M2S(INCLUDE_PATH/inc_radmin3_constants.h)
#endif

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN]; // 1047552 * 4 bytes for PRECOMP_BITS = 10

} radmin3_t;

KERNEL_FQ KERNEL_FA void m29200_mxx (KERN_ATTR_ESALT (radmin3_t))
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

  sha1_update_utf16le_swap (&ctx0, w, pw_len);


  // ctx1 with main salt

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  sha1_update_global (&ctx1, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  PRIVATE_AS const u32 m[64] =
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
  };


  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // add password to the user name (and colon and first part of the password, included):

    sha1_ctx_t c0 = ctx0;

    if (COMBS_IS_MIDDLE)
    {
      // -a 12 puts the base word inside the amplifier, so ctx0 is no longer a prefix of what has to
      // be hashed and the whole candidate goes in behind the user name.

      u32 c[64];

      const u32 c_len = combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    // Each of the two words is bounded at 256 bytes on its own and nothing bounds their sum, but c
    // holds 256 bytes. A pair longer than that cannot be represented here in any case, because
    // switch_buffer_by_offset_1x64_le_S matches no case past the end and the second word would land
    // at offset 0, so the candidate is skipped rather than clamped.

    if (c_len > 256) continue;

      sha1_init (&c0);

      sha1_update_global (&c0, esalt_bufs[DIGESTS_OFFSET_HOST].user, esalt_bufs[DIGESTS_OFFSET_HOST].user_len);

      sha1_update_utf16le_swap (&c0, c, c_len);
    }
    else
    {
      sha1_update_global_utf16le_swap (&c0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }

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

      bn2048_mont_mul (r_t, r_t, pre, m, RADMIN3_N0); // r_t = (r_t * RADMIN3_PRE[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m29200_sxx (KERN_ATTR_ESALT (radmin3_t))
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

  sha1_update_utf16le_swap (&ctx0, w, pw_len);


  // ctx1 with main salt

  sha1_ctx_t ctx1;

  sha1_init (&ctx1);

  sha1_update_global (&ctx1, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  PRIVATE_AS const u32 m[64] =
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
  };


  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // add password to the user name (and colon and first part of the password, included):

    sha1_ctx_t c0 = ctx0;

    if (COMBS_IS_MIDDLE)
    {
      // -a 12 puts the base word inside the amplifier, so ctx0 is no longer a prefix of what has to
      // be hashed and the whole candidate goes in behind the user name.

      u32 c[64];

      const u32 c_len = combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    // Each of the two words is bounded at 256 bytes on its own and nothing bounds their sum, but c
    // holds 256 bytes. A pair longer than that cannot be represented here in any case, because
    // switch_buffer_by_offset_1x64_le_S matches no case past the end and the second word would land
    // at offset 0, so the candidate is skipped rather than clamped.

    if (c_len > 256) continue;

      sha1_init (&c0);

      sha1_update_global (&c0, esalt_bufs[DIGESTS_OFFSET_HOST].user, esalt_bufs[DIGESTS_OFFSET_HOST].user_len);

      sha1_update_utf16le_swap (&c0, c, c_len);
    }
    else
    {
      sha1_update_global_utf16le_swap (&c0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }

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

      bn2048_mont_mul (r_t, r_t, pre, m, RADMIN3_N0); // r_t = (r_t * RADMIN3_PRE[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
