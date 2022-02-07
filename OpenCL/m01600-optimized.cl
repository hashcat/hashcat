/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct md5crypt_tmp
{
  u32 digest_buf[4];

} md5crypt_tmp_t;

#define md5apr1_magic0 0x72706124u
#define md5apr1_magic1 0x00002431u

DECLSPEC void memcat16 (PRIVATE_AS u32 *block0, PRIVATE_AS u32 *block1, PRIVATE_AS u32 *block2, PRIVATE_AS u32 *block3, const u32 offset, PRIVATE_AS const u32 *append)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
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

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  #if defined IS_NV
  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> (offset_minus_4 * 8));
  #endif

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

  const u32 div = offset / 4;

  switch (div)
  {
    case  0:  block0[0] |= tmp0;
              block0[1]  = tmp1;
              block0[2]  = tmp2;
              block0[3]  = tmp3;
              block1[0]  = tmp4;
              break;
    case  1:  block0[1] |= tmp0;
              block0[2]  = tmp1;
              block0[3]  = tmp2;
              block1[0]  = tmp3;
              block1[1]  = tmp4;
              break;
    case  2:  block0[2] |= tmp0;
              block0[3]  = tmp1;
              block1[0]  = tmp2;
              block1[1]  = tmp3;
              block1[2]  = tmp4;
              break;
    case  3:  block0[3] |= tmp0;
              block1[0]  = tmp1;
              block1[1]  = tmp2;
              block1[2]  = tmp3;
              block1[3]  = tmp4;
              break;
    case  4:  block1[0] |= tmp0;
              block1[1]  = tmp1;
              block1[2]  = tmp2;
              block1[3]  = tmp3;
              block2[0]  = tmp4;
              break;
    case  5:  block1[1] |= tmp0;
              block1[2]  = tmp1;
              block1[3]  = tmp2;
              block2[0]  = tmp3;
              block2[1]  = tmp4;
              break;
    case  6:  block1[2] |= tmp0;
              block1[3]  = tmp1;
              block2[0]  = tmp2;
              block2[1]  = tmp3;
              block2[2]  = tmp4;
              break;
    case  7:  block1[3] |= tmp0;
              block2[0]  = tmp1;
              block2[1]  = tmp2;
              block2[2]  = tmp3;
              block2[3]  = tmp4;
              break;
    case  8:  block2[0] |= tmp0;
              block2[1]  = tmp1;
              block2[2]  = tmp2;
              block2[3]  = tmp3;
              block3[0]  = tmp4;
              break;
    case  9:  block2[1] |= tmp0;
              block2[2]  = tmp1;
              block2[3]  = tmp2;
              block3[0]  = tmp3;
              block3[1]  = tmp4;
              break;
  }
}

DECLSPEC void memcat16_x80 (PRIVATE_AS u32 *block0, PRIVATE_AS u32 *block1, PRIVATE_AS u32 *block2, PRIVATE_AS u32 *block3, const u32 offset, PRIVATE_AS const u32 *append)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
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

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  #if defined IS_NV
  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> (offset_minus_4 * 8));
  #endif

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

  const u32 div = offset / 4;

  switch (div)
  {
    case  0:  block0[0] |= tmp0;
              block0[1]  = tmp1;
              block0[2]  = tmp2;
              block0[3]  = tmp3;
              block1[0]  = tmp4;
              break;
    case  1:  block0[1] |= tmp0;
              block0[2]  = tmp1;
              block0[3]  = tmp2;
              block1[0]  = tmp3;
              block1[1]  = tmp4;
              break;
    case  2:  block0[2] |= tmp0;
              block0[3]  = tmp1;
              block1[0]  = tmp2;
              block1[1]  = tmp3;
              block1[2]  = tmp4;
              break;
    case  3:  block0[3] |= tmp0;
              block1[0]  = tmp1;
              block1[1]  = tmp2;
              block1[2]  = tmp3;
              block1[3]  = tmp4;
              break;
    case  4:  block1[0] |= tmp0;
              block1[1]  = tmp1;
              block1[2]  = tmp2;
              block1[3]  = tmp3;
              block2[0]  = tmp4;
              break;
    case  5:  block1[1] |= tmp0;
              block1[2]  = tmp1;
              block1[3]  = tmp2;
              block2[0]  = tmp3;
              block2[1]  = tmp4;
              break;
    case  6:  block1[2] |= tmp0;
              block1[3]  = tmp1;
              block2[0]  = tmp2;
              block2[1]  = tmp3;
              block2[2]  = tmp4;
              break;
    case  7:  block1[3] |= tmp0;
              block2[0]  = tmp1;
              block2[1]  = tmp2;
              block2[2]  = tmp3;
              block2[3]  = tmp4;
              break;
    case  8:  block2[0] |= tmp0;
              block2[1]  = tmp1;
              block2[2]  = tmp2;
              block2[3]  = tmp3;
              block3[0]  = tmp4;
              break;
    case  9:  block2[1] |= tmp0;
              block2[2]  = tmp1;
              block2[3]  = tmp2;
              block3[0]  = tmp3;
              block3[1]  = tmp4;
              break;
  }
}

DECLSPEC void memcat8 (PRIVATE_AS u32 *block0, PRIVATE_AS u32 *block1, PRIVATE_AS u32 *block2, PRIVATE_AS u32 *block3, const u32 offset, PRIVATE_AS const u32 *append)
{
  u32 tmp0;
  u32 tmp1;
  u32 tmp2;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  u32 in0 = append[0];
  u32 in1 = append[1];

  tmp0 = hc_bytealign (  0, in0, offset);
  tmp1 = hc_bytealign (in0, in1, offset);
  tmp2 = hc_bytealign (in1,   0, offset);
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  #if defined IS_NV
  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> (offset_minus_4 * 8));
  #endif

  u32 in0 = append[0];
  u32 in1 = append[1];

  tmp0 = hc_byte_perm (  0, in0, selector);
  tmp1 = hc_byte_perm (in0, in1, selector);
  tmp2 = hc_byte_perm (in1,   0, selector);
  #endif

  const u32 div = offset / 4;

  switch (div)
  {
    case  0:  block0[0] |= tmp0;
              block0[1]  = tmp1;
              block0[2]  = tmp2;
              break;
    case  1:  block0[1] |= tmp0;
              block0[2]  = tmp1;
              block0[3]  = tmp2;
              break;
    case  2:  block0[2] |= tmp0;
              block0[3]  = tmp1;
              block1[0]  = tmp2;
              break;
    case  3:  block0[3] |= tmp0;
              block1[0]  = tmp1;
              block1[1]  = tmp2;
              break;
    case  4:  block1[0] |= tmp0;
              block1[1]  = tmp1;
              block1[2]  = tmp2;
              break;
    case  5:  block1[1] |= tmp0;
              block1[2]  = tmp1;
              block1[3]  = tmp2;
              break;
    case  6:  block1[2] |= tmp0;
              block1[3]  = tmp1;
              block2[0]  = tmp2;
              break;
    case  7:  block1[3] |= tmp0;
              block2[0]  = tmp1;
              block2[1]  = tmp2;
              break;
    case  8:  block2[0] |= tmp0;
              block2[1]  = tmp1;
              block2[2]  = tmp2;
              break;
    case  9:  block2[1] |= tmp0;
              block2[2]  = tmp1;
              block2[3]  = tmp2;
              break;
    case 10:  block2[2] |= tmp0;
              block2[3]  = tmp1;
              block3[0]  = tmp2;
              break;
    case 11:  block2[3] |= tmp0;
              block3[0]  = tmp1;
              block3[1]  = tmp2;
              break;
  }
}

DECLSPEC void append_sign (PRIVATE_AS u32 *block0, PRIVATE_AS u32 *block1, const u32 block_len)
{
  switch (block_len)
  {
    case 0:
      block0[0] = md5apr1_magic0;
      block0[1] = md5apr1_magic1;
      break;

    case 1:
      block0[0] = block0[0]             | md5apr1_magic0 <<  8u;
      block0[1] = md5apr1_magic0 >> 24u | md5apr1_magic1 <<  8u;
      block0[2] = md5apr1_magic1 >> 24u;
      break;

    case 2:
      block0[0] = block0[0]             | md5apr1_magic0 << 16u;
      block0[1] = md5apr1_magic0 >> 16u | md5apr1_magic1 << 16u;
      block0[2] = md5apr1_magic1 >> 16u;
      break;

    case 3:
      block0[0] = block0[0]             | md5apr1_magic0 << 24u;
      block0[1] = md5apr1_magic0 >>  8u | md5apr1_magic1 << 24u;
      block0[2] = md5apr1_magic1 >>  8u;
      break;

    case 4:
      block0[1] = md5apr1_magic0;
      block0[2] = md5apr1_magic1;
      break;

    case 5:
      block0[1] = block0[1]             | md5apr1_magic0 <<  8u;
      block0[2] = md5apr1_magic0 >> 24u | md5apr1_magic1 <<  8u;
      block0[3] = md5apr1_magic1 >> 24u;
      break;

    case 6:
      block0[1] = block0[1]             | md5apr1_magic0 << 16u;
      block0[2] = md5apr1_magic0 >> 16u | md5apr1_magic1 << 16u;
      block0[3] = md5apr1_magic1 >> 16u;
      break;

    case 7:
      block0[1] = block0[1]             | md5apr1_magic0 << 24u;
      block0[2] = md5apr1_magic0 >>  8u | md5apr1_magic1 << 24u;
      block0[3] = md5apr1_magic1 >>  8u;
      break;

    case 8:
      block0[2] = md5apr1_magic0;
      block0[3] = md5apr1_magic1;
      break;

    case 9:
      block0[2] = block0[2]             | md5apr1_magic0 <<  8u;
      block0[3] = md5apr1_magic0 >> 24u | md5apr1_magic1 <<  8u;
      block1[0] = md5apr1_magic1 >> 24u;
      break;

    case 10:
      block0[2] = block0[2]             | md5apr1_magic0 << 16u;
      block0[3] = md5apr1_magic0 >> 16u | md5apr1_magic1 << 16u;
      block1[0] = md5apr1_magic1 >> 16u;
      break;

    case 11:
      block0[2] = block0[2]             | md5apr1_magic0 << 24u;
      block0[3] = md5apr1_magic0 >>  8u | md5apr1_magic1 << 24u;
      block1[0] = md5apr1_magic1 >>  8u;
      break;

    case 12:
      block0[3] = md5apr1_magic0;
      block1[0] = md5apr1_magic1;
      break;

    case 13:
      block0[3] = block0[3]             | md5apr1_magic0 <<  8u;
      block1[0] = md5apr1_magic0 >> 24u | md5apr1_magic1 <<  8u;
      block1[1] = md5apr1_magic1 >> 24u;
      break;

    case 14:
      block0[3] = block0[3]             | md5apr1_magic0 << 16u;
      block1[0] = md5apr1_magic0 >> 16u | md5apr1_magic1 << 16u;
      block1[1] = md5apr1_magic1 >> 16u;
      break;

    case 15:
      block0[3] = block0[3]             | md5apr1_magic0 << 24u;
      block1[0] = md5apr1_magic0 >>  8u | md5apr1_magic1 << 24u;
      block1[1] = md5apr1_magic1 >>  8u;
      break;
  }
}

DECLSPEC void append_1st (PRIVATE_AS u32 *block0, PRIVATE_AS u32 *block1, PRIVATE_AS u32 *block2, PRIVATE_AS u32 *block3, const u32 block_len, const u32 append)
{
  switch (block_len)
  {
    case 0:
      block0[0] = append;
      break;

    case 1:
      block0[0] = block0[0] | append <<  8;
      break;

    case 2:
      block0[0] = block0[0] | append << 16;
      break;

    case 3:
      block0[0] = block0[0] | append << 24;
      break;

    case 4:
      block0[1] = append;
      break;

    case 5:
      block0[1] = block0[1] | append <<  8;
      break;

    case 6:
      block0[1] = block0[1] | append << 16;
      break;

    case 7:
      block0[1] = block0[1] | append << 24;
      break;

    case 8:
      block0[2] = append;
      break;

    case 9:
      block0[2] = block0[2] | append <<  8;
      break;

    case 10:
      block0[2] = block0[2] | append << 16;
      break;

    case 11:
      block0[2] = block0[2] | append << 24;
      break;

    case 12:
      block0[3] = append;
      break;

    case 13:
      block0[3] = block0[3] | append <<  8;
      break;

    case 14:
      block0[3] = block0[3] | append << 16;
      break;

    case 15:
      block0[3] = block0[3] | append << 24;
      break;

    case 16:
      block1[0] = append;
      break;

    case 17:
      block1[0] = block1[0] | append <<  8;
      break;

    case 18:
      block1[0] = block1[0] | append << 16;
      break;

    case 19:
      block1[0] = block1[0] | append << 24;
      break;

    case 20:
      block1[1] = append;
      break;

    case 21:
      block1[1] = block1[1] | append <<  8;
      break;

    case 22:
      block1[1] = block1[1] | append << 16;
      break;

    case 23:
      block1[1] = block1[1] | append << 24;
      break;

    case 24:
      block1[2] = append;
      break;

    case 25:
      block1[2] = block1[2] | append <<  8;
      break;

    case 26:
      block1[2] = block1[2] | append << 16;
      break;

    case 27:
      block1[2] = block1[2] | append << 24;
      break;

    case 28:
      block1[3] = append;
      break;

    case 29:
      block1[3] = block1[3] | append <<  8;
      break;

    case 30:
      block1[3] = block1[3] | append << 16;
      break;

    case 31:
      block1[3] = block1[3] | append << 24;
      break;

    case 32:
      block2[0] = append;
      break;

    case 33:
      block2[0] = block2[0] | append <<  8;
      break;

    case 34:
      block2[0] = block2[0] | append << 16;
      break;

    case 35:
      block2[0] = block2[0] | append << 24;
      break;

    case 36:
      block2[1] = append;
      break;

    case 37:
      block2[1] = block2[1] | append <<  8;
      break;

    case 38:
      block2[1] = block2[1] | append << 16;
      break;

    case 39:
      block2[1] = block2[1] | append << 24;
      break;

    case 40:
      block2[2] = append;
      break;

    case 41:
      block2[2] = block2[2] | append <<  8;
      break;

    case 42:
      block2[2] = block2[2] | append << 16;
      break;

    case 43:
      block2[2] = block2[2] | append << 24;
      break;

    case 44:
      block2[3] = append;
      break;

    case 45:
      block2[3] = block2[3] | append <<  8;
      break;

    case 46:
      block2[3] = block2[3] | append << 16;
      break;

    case 47:
      block2[3] = block2[3] | append << 24;
      break;

    case 48:
      block3[0] = append;
      break;

    case 49:
      block3[0] = block3[0] | append <<  8;
      break;

    case 50:
      block3[0] = block3[0] | append << 16;
      break;

    case 51:
      block3[0] = block3[0] | append << 24;
      break;

    case 52:
      block3[1] = append;
      break;

    case 53:
      block3[1] = block3[1] | append <<  8;
      break;

    case 54:
      block3[1] = block3[1] | append << 16;
      break;

    case 55:
      block3[1] = block3[1] | append << 24;
      break;

    case 56:
      block3[2] = append;
      break;
  }
}

KERNEL_FQ void m01600_init (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  /**
   * init
   */

  //memcat16 (block0, block1, block2, block3, block_len, w0);
  //block_len += pw_len;

  u32 block_len = pw_len;

  u32 block0[4];

  block0[0] = w0[0];
  block0[1] = w0[1];
  block0[2] = w0[2];
  block0[3] = w0[3];

  u32 block1[4];

  block1[0] = 0;
  block1[1] = 0;
  block1[2] = 0;
  block1[3] = 0;

  u32 block2[4];

  block2[0] = 0;
  block2[1] = 0;
  block2[2] = 0;
  block2[3] = 0;

  u32 block3[4];

  block3[0] = 0;
  block3[1] = 0;
  block3[2] = 0;
  block3[3] = 0;

  memcat8 (block0, block1, block2, block3, block_len, salt_buf);

  block_len += salt_len;

  memcat16 (block0, block1, block2, block3, block_len, w0);

  block_len += pw_len;

  append_0x80_4x4 (block0, block1, block2, block3, block_len);

  block3[2] = block_len * 8;

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (block0, block1, block2, block3, digest);

  /* The password first, since that is what is most unknown */
  /* Then our magic string */
  /* Then the raw salt */
  /* Then just as many characters of the MD5(pw,salt,pw) */

  //memcat16 (block0, block1, block2, block3, block_len, w);
  //block_len += pw_len;

  block_len = pw_len;

  block0[0] = w0[0];
  block0[1] = w0[1];
  block0[2] = w0[2];
  block0[3] = w0[3];

  block1[0] = 0;
  block1[1] = 0;
  block1[2] = 0;
  block1[3] = 0;

  block2[0] = 0;
  block2[1] = 0;
  block2[2] = 0;
  block2[3] = 0;

  block3[0] = 0;
  block3[1] = 0;
  block3[2] = 0;
  block3[3] = 0;

  append_sign (block0, block1, block_len);

  block_len += 6;

  memcat8 (block0, block1, block2, block3, block_len, salt_buf);

  block_len += salt_len;

  truncate_block_4x4_le_S (digest, pw_len);

  memcat16 (block0, block1, block2, block3, block_len, digest);

  block_len += pw_len;

  /* Then something really weird... */

  u32 append = block0[0] & 0xFF;

  for (u32 j = pw_len; j; j >>= 1)
  {
    if ((j & 1) == 0)
    {
      append_1st (block0, block1, block2, block3, block_len, append);
    }

    block_len++;
  }

  append_0x80_4x4 (block0, block1, block2, block3, block_len);

  block3[2] = block_len * 8;

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (block0, block1, block2, block3, digest);

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m01600_loop (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len & 63;

  u32 w0_x80[4];

  w0_x80[0] = w0[0];
  w0_x80[1] = w0[1];
  w0_x80[2] = w0[2];
  w0_x80[3] = w0[3];

  append_0x80_1x4 (w0_x80, pw_len);

  /**
   * salt
   */

  u32 salt_buf[2];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  /**
   * digest
   */

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  /**
   * loop
   */

  /* and now, just to make sure things don't run too fast */

  u32 block_len;

  u32 block0[4];

  block0[0] = 0;
  block0[1] = 0;
  block0[2] = 0;
  block0[3] = 0;

  u32 block1[4];

  block1[0] = 0;
  block1[1] = 0;
  block1[2] = 0;
  block1[3] = 0;

  u32 block2[4];

  block2[0] = 0;
  block2[1] = 0;
  block2[2] = 0;
  block2[3] = 0;

  u32 block3[4];

  block3[0] = 0;
  block3[1] = 0;
  block3[2] = 0;
  block3[3] = 0;

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    block1[0] = 0;
    block1[1] = 0;
    block1[2] = 0;
    block1[3] = 0;
    block2[0] = 0;
    block2[1] = 0;
    block2[2] = 0;
    block2[3] = 0;
    block3[0] = 0;
    block3[1] = 0;

    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 1 : 0;
    const u32 j7 = (j % 7) ? 1 : 0;

    if (j1)
    {
      block0[0] = w0[0];
      block0[1] = w0[1];
      block0[2] = w0[2];
      block0[3] = w0[3];

      block_len = pw_len;

      if (j3)
      {
        memcat8 (block0, block1, block2, block3, block_len, salt_buf);

        block_len += salt_len;
      }

      if (j7)
      {
        memcat16 (block0, block1, block2, block3, block_len, w0);

        block_len += pw_len;
      }

      memcat16_x80 (block0, block1, block2, block3, block_len, digest);

      block_len += 16;
    }
    else
    {
      block0[0] = digest[0];
      block0[1] = digest[1];
      block0[2] = digest[2];
      block0[3] = digest[3];

      block_len = 16;

      if (j3 && j7)
      {
        block1[0] = salt_buf[0];
        block1[1] = salt_buf[1];

        block_len += salt_len;

        memcat16 (block0, block1, block2, block3, block_len, w0);

        block_len += pw_len;
      }
      else if (j3)
      {
        block1[0] = salt_buf[0];
        block1[1] = salt_buf[1];

        block_len += salt_len;
      }
      else if (j7)
      {
        block1[0] = w0[0];
        block1[1] = w0[1];
        block1[2] = w0[2];
        block1[3] = w0[3];

        block_len += pw_len;
      }

      memcat16 (block0, block1, block2, block3, block_len, w0_x80);

      block_len += pw_len;
    }

    block3[2] = block_len * 8;

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (block0, block1, block2, block3, digest);
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m01600_comp (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
