/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define IS_GENERIC

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "cpu_md5.h"

void md5_64 (const u32 block[16], u32 digest[4])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = block[ 0];
  w0[1] = block[ 1];
  w0[2] = block[ 2];
  w0[3] = block[ 3];
  w1[0] = block[ 4];
  w1[1] = block[ 5];
  w1[2] = block[ 6];
  w1[3] = block[ 7];
  w2[0] = block[ 8];
  w2[1] = block[ 9];
  w2[2] = block[10];
  w2[3] = block[11];
  w3[0] = block[12];
  w3[1] = block[13];
  w3[2] = block[14];
  w3[3] = block[15];

  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

  MD5_STEP (MD5_H , a, b, c, d, w1[1], MD5C20, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w2[0], MD5C21, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w2[3], MD5C22, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w3[2], MD5C23, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w0[1], MD5C24, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w1[0], MD5C25, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w1[3], MD5C26, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w2[2], MD5C27, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w3[1], MD5C28, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w0[0], MD5C29, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w0[3], MD5C2a, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w1[2], MD5C2b, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w2[1], MD5C2c, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w3[0], MD5C2d, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w3[3], MD5C2e, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w0[2], MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

// only use this when really, really needed, SLOW

void md5_complete_no_limit (u32 digest[4], const u32 *plain, const u32 plain_len)
{
  u32 a = MD5M_A;
  u32 b = MD5M_B;
  u32 c = MD5M_C;
  u32 d = MD5M_D;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;

  u32 r_a = digest[0];
  u32 r_b = digest[1];
  u32 r_c = digest[2];
  u32 r_d = digest[3];

  u32 block[16];
  int  block_total_len = 16 * 4; // sizeof (block)

  char *block_ptr = (char *) block;
  char *plain_ptr = (char *) plain;

  // init

  int remaining_len = (int) plain_len;

  // loop

  u32 loop = 1;

  while (loop)
  {
    loop = (remaining_len > 55);

    int cur_len  = MIN (block_total_len, remaining_len);
    int copy_len = MAX (cur_len, 0);  // should never be negative of course

    // initialize the block

    memset (block_ptr, 0, block_total_len);

    // copy the bytes from the plain pointer (plain_ptr)

    memcpy (block_ptr, plain_ptr, (size_t) copy_len);

    /*
     * final block
     */

    // set 0x80 if needed

    if (cur_len >= 0)
    {
      if (copy_len < block_total_len)
      {
        block_ptr[copy_len] = (char) 0x80;
      }
    }

    // set block[14] set to total_len

    if (! loop) block[14] = plain_len * 8;

    /*
     * md5 ()
     */

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = block[ 0];
    w0[1] = block[ 1];
    w0[2] = block[ 2];
    w0[3] = block[ 3];
    w1[0] = block[ 4];
    w1[1] = block[ 5];
    w1[2] = block[ 6];
    w1[3] = block[ 7];
    w2[0] = block[ 8];
    w2[1] = block[ 9];
    w2[2] = block[10];
    w2[3] = block[11];
    w3[0] = block[12];
    w3[1] = block[13];
    w3[2] = block[14];
    w3[3] = block[15];

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    remaining_len -= block_total_len;

    plain_ptr += 64;

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    digest[0] = a;
    digest[1] = b;
    digest[2] = c;
    digest[3] = d;

    r_a = digest[0];
    r_b = digest[1];
    r_c = digest[2];
    r_d = digest[3];
  }
}
