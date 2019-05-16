/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_sha256.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct sha256crypt_tmp
{
  // pure version

  u32 alt_result[8];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha256crypt_tmp_t;

DECLSPEC void sha256_transform_transport (const u32 *w, u32 *digest)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc_swap32_S (w[ 0]);
  w0[1] = hc_swap32_S (w[ 1]);
  w0[2] = hc_swap32_S (w[ 2]);
  w0[3] = hc_swap32_S (w[ 3]);
  w1[0] = hc_swap32_S (w[ 4]);
  w1[1] = hc_swap32_S (w[ 5]);
  w1[2] = hc_swap32_S (w[ 6]);
  w1[3] = hc_swap32_S (w[ 7]);
  w2[0] = hc_swap32_S (w[ 8]);
  w2[1] = hc_swap32_S (w[ 9]);
  w2[2] = hc_swap32_S (w[10]);
  w2[3] = hc_swap32_S (w[11]);
  w3[0] = hc_swap32_S (w[12]);
  w3[1] = hc_swap32_S (w[13]);
  w3[2] = hc_swap32_S (w[14]);
  w3[3] = hc_swap32_S (w[15]);

  sha256_transform (w0, w1, w2, w3, digest);
}

DECLSPEC void init_ctx (u32 *digest)
{
  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;
}

DECLSPEC void bzero16 (u32 *block)
{
  block[ 0] = 0;
  block[ 1] = 0;
  block[ 2] = 0;
  block[ 3] = 0;
  block[ 4] = 0;
  block[ 5] = 0;
  block[ 6] = 0;
  block[ 7] = 0;
  block[ 8] = 0;
  block[ 9] = 0;
  block[10] = 0;
  block[11] = 0;
  block[12] = 0;
  block[13] = 0;
  block[14] = 0;
  block[15] = 0;
}

DECLSPEC void bswap8 (u32 *block)
{
  block[ 0] = hc_swap32_S (block[ 0]);
  block[ 1] = hc_swap32_S (block[ 1]);
  block[ 2] = hc_swap32_S (block[ 2]);
  block[ 3] = hc_swap32_S (block[ 3]);
  block[ 4] = hc_swap32_S (block[ 4]);
  block[ 5] = hc_swap32_S (block[ 5]);
  block[ 6] = hc_swap32_S (block[ 6]);
  block[ 7] = hc_swap32_S (block[ 7]);
}

DECLSPEC u32 memcat16 (u32 *block, const u32 offset, const u32 *append, const u32 append_len)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_bytealign (  0, in0, offset);
  tmp1 = hc_bytealign (in0, in1, offset);
  tmp2 = hc_bytealign (in1, in2, offset);
  tmp3 = hc_bytealign (in2, in3, offset);
  tmp4 = hc_bytealign (in3,   0, offset);
  #endif

  #ifdef IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_byte_perm (  0, in0, selector);
  tmp1 = hc_byte_perm (in0, in1, selector);
  tmp2 = hc_byte_perm (in1, in2, selector);
  tmp3 = hc_byte_perm (in2, in3, selector);
  tmp4 = hc_byte_perm (in3,   0, selector);
  #endif

  switch (offset / 4)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              break;
    case 15:  block[15] |= tmp0;
              break;
  }

  u32 new_len = offset + append_len;

  return new_len;
}

DECLSPEC u32 memcat16c (u32 *block, const u32 offset, const u32 *append, const u32 append_len, u32 *digest)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_bytealign (  0, in0, offset);
  tmp1 = hc_bytealign (in0, in1, offset);
  tmp2 = hc_bytealign (in1, in2, offset);
  tmp3 = hc_bytealign (in2, in3, offset);
  tmp4 = hc_bytealign (in3,   0, offset);
  #endif

  #ifdef IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_byte_perm (  0, in0, selector);
  tmp1 = hc_byte_perm (in0, in1, selector);
  tmp2 = hc_byte_perm (in1, in2, selector);
  tmp3 = hc_byte_perm (in2, in3, selector);
  tmp4 = hc_byte_perm (in3,   0, selector);
  #endif

  u32 carry[4] = { 0, 0, 0, 0 };

  switch (offset / 4)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              carry[ 0]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              carry[ 0]  = tmp3;
              carry[ 1]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              carry[ 0]  = tmp2;
              carry[ 1]  = tmp3;
              carry[ 2]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              carry[ 0]  = tmp1;
              carry[ 1]  = tmp2;
              carry[ 2]  = tmp3;
              carry[ 3]  = tmp4;
              break;
  }

  u32 new_len = offset + append_len;

  if (new_len >= 64)
  {
    new_len -= 64;

    sha256_transform_transport (block, digest);

    bzero16 (block);

    block[0] = carry[0];
    block[1] = carry[1];
    block[2] = carry[2];
    block[3] = carry[3];
  }

  return new_len;
}

DECLSPEC u32 memcat20 (u32 *block, const u32 offset, const u32 *append, const u32 append_len)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_bytealign (  0, in0, offset);
  tmp1 = hc_bytealign (in0, in1, offset);
  tmp2 = hc_bytealign (in1, in2, offset);
  tmp3 = hc_bytealign (in2, in3, offset);
  tmp4 = hc_bytealign (in3,   0, offset);
  #endif

  #ifdef IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];

  tmp0 = hc_byte_perm (  0, in0, selector);
  tmp1 = hc_byte_perm (in0, in1, selector);
  tmp2 = hc_byte_perm (in1, in2, selector);
  tmp3 = hc_byte_perm (in2, in3, selector);
  tmp4 = hc_byte_perm (in3,   0, selector);
  #endif

  switch (offset / 4)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              block[16]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              block[16]  = tmp3;
              block[17]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              block[16]  = tmp2;
              block[17]  = tmp3;
              block[18]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              block[16]  = tmp1;
              block[17]  = tmp2;
              block[18]  = tmp3;
              block[19]  = tmp4;
              break;
  }

  return offset + append_len;
}

DECLSPEC u32 memcat20_x80 (u32 *block, const u32 offset, const u32 *append, const u32 append_len)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];
  u32 in4 = 0x80;

  tmp0 = hc_bytealign (  0, in0, offset);
  tmp1 = hc_bytealign (in0, in1, offset);
  tmp2 = hc_bytealign (in1, in2, offset);
  tmp3 = hc_bytealign (in2, in3, offset);
  tmp4 = hc_bytealign (in3, in4, offset);
  #endif

  #ifdef IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32 in0 = append[0];
  u32 in1 = append[1];
  u32 in2 = append[2];
  u32 in3 = append[3];
  u32 in4 = 0x80;

  tmp0 = hc_byte_perm (  0, in0, selector);
  tmp1 = hc_byte_perm (in0, in1, selector);
  tmp2 = hc_byte_perm (in1, in2, selector);
  tmp3 = hc_byte_perm (in2, in3, selector);
  tmp4 = hc_byte_perm (in3, in4, selector);
  #endif

  switch (offset / 4)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              block[16]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              block[16]  = tmp3;
              block[17]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              block[16]  = tmp2;
              block[17]  = tmp3;
              block[18]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              block[16]  = tmp1;
              block[17]  = tmp2;
              block[18]  = tmp3;
              block[19]  = tmp4;
              break;
  }

  return offset + append_len;
}

KERNEL_FQ void m07400_init (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * buffers
   */

  u32 block_len;     // never reaches > 64
  u32 transform_len; // required for w[15] = len * 8

  u32 block[16];

  u32 alt_result[8];
  u32 p_bytes[8];
  u32 s_bytes[8];

  /* Prepare for the real work.  */

  block_len = 0;

  bzero16 (block);

  /* Add key.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  /* Add salt.  */

  block_len = memcat16 (block, block_len, salt_buf, salt_len);

  /* Add key again.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  append_0x80_1x16 (block, block_len);

  block[15] = hc_swap32_S (block_len * 8);

  init_ctx (alt_result);

  sha256_transform_transport (block, alt_result);

  bswap8 (alt_result);

  block_len = 0;

  bzero16 (block);

  u32 alt_result_tmp[8];

  alt_result_tmp[0] = alt_result[0];
  alt_result_tmp[1] = alt_result[1];
  alt_result_tmp[2] = alt_result[2];
  alt_result_tmp[3] = alt_result[3];
  alt_result_tmp[4] = 0;
  alt_result_tmp[5] = 0;
  alt_result_tmp[6] = 0;
  alt_result_tmp[7] = 0;

  truncate_block_4x4_le_S (alt_result_tmp, pw_len);

  /* Add the key string.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */

  block_len = memcat16 (block, block_len, salt_buf, salt_len);

  /* Now get result of this (32 bytes) and add it to the other
     context.  */

  block_len = memcat16 (block, block_len, alt_result_tmp, pw_len);

  transform_len = block_len;

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */

  alt_result_tmp[0] = alt_result[0];
  alt_result_tmp[1] = alt_result[1];
  alt_result_tmp[2] = alt_result[2];
  alt_result_tmp[3] = alt_result[3];
  alt_result_tmp[4] = alt_result[4];
  alt_result_tmp[5] = alt_result[5];
  alt_result_tmp[6] = alt_result[6];
  alt_result_tmp[7] = alt_result[7];

  init_ctx (alt_result);

  for (u32 j = pw_len; j; j >>= 1)
  {
    if (j & 1)
    {
      block_len = memcat16c (block, block_len, &alt_result_tmp[0], 16, alt_result);
      block_len = memcat16c (block, block_len, &alt_result_tmp[4], 16, alt_result);

      transform_len += 32;
    }
    else
    {
      block_len = memcat16c (block, block_len, w0, pw_len, alt_result);

      transform_len += pw_len;
    }
  }

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform_transport (block, alt_result);

    bzero16 (block);
  }

  block[15] = hc_swap32_S (transform_len * 8);

  sha256_transform_transport (block, alt_result);

  bswap8 (alt_result);

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];

  /* Start computation of P byte sequence.  */

  block_len = 0;

  transform_len = 0;

  bzero16 (block);

  /* For every character in the password add the entire password.  */

  init_ctx (p_bytes);

  for (u32 j = 0; j < pw_len; j++)
  {
    block_len = memcat16c (block, block_len, w0, pw_len, p_bytes);

    transform_len += pw_len;
  }

  /* Finish the digest.  */

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform_transport (block, p_bytes);

    bzero16 (block);
  }

  block[15] = hc_swap32_S (transform_len * 8);

  sha256_transform_transport (block, p_bytes);

  bswap8 (p_bytes);

  truncate_block_4x4_le_S (p_bytes, pw_len);

  tmps[gid].p_bytes[0] = p_bytes[0];
  tmps[gid].p_bytes[1] = p_bytes[1];
  tmps[gid].p_bytes[2] = p_bytes[2];
  tmps[gid].p_bytes[3] = p_bytes[3];

  /* Start computation of S byte sequence.  */

  block_len = 0;

  transform_len = 0;

  bzero16 (block);

  /* For every character in the password add the entire password.  */

  init_ctx (s_bytes);

  for (u32 j = 0; j < 16 + (alt_result[0] & 0xff); j++)
  {
    block_len = memcat16c (block, block_len, salt_buf, salt_len, s_bytes);

    transform_len += salt_len;
  }

  /* Finish the digest.  */

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform_transport (block, s_bytes);

    bzero16 (block);
  }

  block[15] = hc_swap32_S (transform_len * 8);

  sha256_transform_transport (block, s_bytes);

  bswap8 (s_bytes);

  truncate_block_4x4_le_S (s_bytes, salt_len);

  tmps[gid].s_bytes[0] = s_bytes[0];
  tmps[gid].s_bytes[1] = s_bytes[1];
  tmps[gid].s_bytes[2] = s_bytes[2];
  tmps[gid].s_bytes[3] = s_bytes[3];
}

KERNEL_FQ void m07400_loop (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * base
   */

  u32 p_bytes[4];

  p_bytes[0] = tmps[gid].p_bytes[0];
  p_bytes[1] = tmps[gid].p_bytes[1];
  p_bytes[2] = tmps[gid].p_bytes[2];
  p_bytes[3] = tmps[gid].p_bytes[3];

  u32 p_bytes_x80[4];

  p_bytes_x80[0] = tmps[gid].p_bytes[0];
  p_bytes_x80[1] = tmps[gid].p_bytes[1];
  p_bytes_x80[2] = tmps[gid].p_bytes[2];
  p_bytes_x80[3] = tmps[gid].p_bytes[3];

  append_0x80_1x4 (p_bytes_x80, pw_len);

  u32 s_bytes[4];

  s_bytes[0] = tmps[gid].s_bytes[0];
  s_bytes[1] = tmps[gid].s_bytes[1];
  s_bytes[2] = tmps[gid].s_bytes[2];
  s_bytes[3] = tmps[gid].s_bytes[3];

  u32 alt_result[8];

  alt_result[0] = tmps[gid].alt_result[0];
  alt_result[1] = tmps[gid].alt_result[1];
  alt_result[2] = tmps[gid].alt_result[2];
  alt_result[3] = tmps[gid].alt_result[3];
  alt_result[4] = tmps[gid].alt_result[4];
  alt_result[5] = tmps[gid].alt_result[5];
  alt_result[6] = tmps[gid].alt_result[6];
  alt_result[7] = tmps[gid].alt_result[7];

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    u32 tmp[8];

    init_ctx (tmp);

    u32 block[32];

    bzero16 (&block[ 0]);
    bzero16 (&block[16]);

    u32 block_len = 0;

    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 1 : 0;
    const u32 j7 = (j % 7) ? 1 : 0;

    if (j1)
    {
      block[0] = p_bytes[0];
      block[1] = p_bytes[1];
      block[2] = p_bytes[2];
      block[3] = p_bytes[3];

      block_len = pw_len;
    }
    else
    {
      block[0] = alt_result[0];
      block[1] = alt_result[1];
      block[2] = alt_result[2];
      block[3] = alt_result[3];
      block[4] = alt_result[4];
      block[5] = alt_result[5];
      block[6] = alt_result[6];
      block[7] = alt_result[7];

      block_len = 32;
    }

    if (j3)
    {
      block_len = memcat20 (block, block_len, s_bytes, salt_len);
    }

    if (j7)
    {
      block_len = memcat20 (block, block_len, p_bytes, pw_len);
    }

    if (j1)
    {
      block_len = memcat20     (block, block_len, &alt_result[0], 16);
      block_len = memcat20_x80 (block, block_len, &alt_result[4], 16);
    }
    else
    {
      block_len = memcat20 (block, block_len, p_bytes_x80, pw_len);
    }

    if (block_len >= 56)
    {
      sha256_transform_transport (block, tmp);

      block[ 0] = block[16];
      block[ 1] = block[17];
      block[ 2] = block[18];
      block[ 3] = block[19];
      block[ 4] = 0;
      block[ 5] = 0;
      block[ 6] = 0;
      block[ 7] = 0;
      block[ 8] = 0;
      block[ 9] = 0;
      block[10] = 0;
      block[11] = 0;
      block[12] = 0;
      block[13] = 0;
      block[14] = 0;
      block[15] = 0;
    }

    block[15] = hc_swap32_S (block_len * 8);

    sha256_transform_transport (block, tmp);

    bswap8 (tmp);

    alt_result[0] = tmp[0];
    alt_result[1] = tmp[1];
    alt_result[2] = tmp[2];
    alt_result[3] = tmp[3];
    alt_result[4] = tmp[4];
    alt_result[5] = tmp[5];
    alt_result[6] = tmp[6];
    alt_result[7] = tmp[7];
  }

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];
}

KERNEL_FQ void m07400_comp (KERN_ATTR_TMPS (sha256crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 r0 = tmps[gid].alt_result[0];
  const u32 r1 = tmps[gid].alt_result[1];
  const u32 r2 = tmps[gid].alt_result[2];
  const u32 r3 = tmps[gid].alt_result[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
