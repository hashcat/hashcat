#define MAGIC_A 0x67452301
#define MAGIC_B 0xefcdab89
#define MAGIC_C 0x98badcfe
#define MAGIC_D 0x10325476

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (ac); \
   (a) = rotl32 ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (ac); \
   (a) = rotl32 ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (ac); \
   (a) = rotl32 ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (ac); \
   (a) = rotl32 ((a), (s)); \
   (a) += (b); \
  }

void md5_64 (uint block[16], uint digest[4])
{
  uint a = digest[0];
  uint b = digest[1];
  uint c = digest[2];
  uint d = digest[3];

  #define S11 7
  #define S12 12
  #define S13 17
  #define S14 22

  FF ( a, b, c, d, block[ 0], S11, 0xd76aa478);
  FF ( d, a, b, c, block[ 1], S12, 0xe8c7b756);
  FF ( c, d, a, b, block[ 2], S13, 0x242070db);
  FF ( b, c, d, a, block[ 3], S14, 0xc1bdceee);
  FF ( a, b, c, d, block[ 4], S11, 0xf57c0faf);
  FF ( d, a, b, c, block[ 5], S12, 0x4787c62a);
  FF ( c, d, a, b, block[ 6], S13, 0xa8304613);
  FF ( b, c, d, a, block[ 7], S14, 0xfd469501);
  FF ( a, b, c, d, block[ 8], S11, 0x698098d8);
  FF ( d, a, b, c, block[ 9], S12, 0x8b44f7af);
  FF ( c, d, a, b, block[10], S13, 0xffff5bb1);
  FF ( b, c, d, a, block[11], S14, 0x895cd7be);
  FF ( a, b, c, d, block[12], S11, 0x6b901122);
  FF ( d, a, b, c, block[13], S12, 0xfd987193);
  FF ( c, d, a, b, block[14], S13, 0xa679438e);
  FF ( b, c, d, a, block[15], S14, 0x49b40821);

  #define S21 5
  #define S22 9
  #define S23 14
  #define S24 20

  GG ( a, b, c, d, block[ 1], S21, 0xf61e2562);
  GG ( d, a, b, c, block[ 6], S22, 0xc040b340);
  GG ( c, d, a, b, block[11], S23, 0x265e5a51);
  GG ( b, c, d, a, block[ 0], S24, 0xe9b6c7aa);
  GG ( a, b, c, d, block[ 5], S21, 0xd62f105d);
  GG ( d, a, b, c, block[10], S22, 0x02441453);
  GG ( c, d, a, b, block[15], S23, 0xd8a1e681);
  GG ( b, c, d, a, block[ 4], S24, 0xe7d3fbc8);
  GG ( a, b, c, d, block[ 9], S21, 0x21e1cde6);
  GG ( d, a, b, c, block[14], S22, 0xc33707d6);
  GG ( c, d, a, b, block[ 3], S23, 0xf4d50d87);
  GG ( b, c, d, a, block[ 8], S24, 0x455a14ed);
  GG ( a, b, c, d, block[13], S21, 0xa9e3e905);
  GG ( d, a, b, c, block[ 2], S22, 0xfcefa3f8);
  GG ( c, d, a, b, block[ 7], S23, 0x676f02d9);
  GG ( b, c, d, a, block[12], S24, 0x8d2a4c8a);

  #define S31 4
  #define S32 11
  #define S33 16
  #define S34 23

  HH ( a, b, c, d, block[ 5], S31, 0xfffa3942);
  HH ( d, a, b, c, block[ 8], S32, 0x8771f681);
  HH ( c, d, a, b, block[11], S33, 0x6d9d6122);
  HH ( b, c, d, a, block[14], S34, 0xfde5380c);
  HH ( a, b, c, d, block[ 1], S31, 0xa4beea44);
  HH ( d, a, b, c, block[ 4], S32, 0x4bdecfa9);
  HH ( c, d, a, b, block[ 7], S33, 0xf6bb4b60);
  HH ( b, c, d, a, block[10], S34, 0xbebfbc70);
  HH ( a, b, c, d, block[13], S31, 0x289b7ec6);
  HH ( d, a, b, c, block[ 0], S32, 0xeaa127fa);
  HH ( c, d, a, b, block[ 3], S33, 0xd4ef3085);
  HH ( b, c, d, a, block[ 6], S34, 0x04881d05);
  HH ( a, b, c, d, block[ 9], S31, 0xd9d4d039);
  HH ( d, a, b, c, block[12], S32, 0xe6db99e5);
  HH ( c, d, a, b, block[15], S33, 0x1fa27cf8);
  HH ( b, c, d, a, block[ 2], S34, 0xc4ac5665);

  #define S41 6
  #define S42 10
  #define S43 15
  #define S44 21

  II ( a, b, c, d, block[ 0], S41, 0xf4292244);
  II ( d, a, b, c, block[ 7], S42, 0x432aff97);
  II ( c, d, a, b, block[14], S43, 0xab9423a7);
  II ( b, c, d, a, block[ 5], S44, 0xfc93a039);
  II ( a, b, c, d, block[12], S41, 0x655b59c3);
  II ( d, a, b, c, block[ 3], S42, 0x8f0ccc92);
  II ( c, d, a, b, block[10], S43, 0xffeff47d);
  II ( b, c, d, a, block[ 1], S44, 0x85845dd1);
  II ( a, b, c, d, block[ 8], S41, 0x6fa87e4f);
  II ( d, a, b, c, block[15], S42, 0xfe2ce6e0);
  II ( c, d, a, b, block[ 6], S43, 0xa3014314);
  II ( b, c, d, a, block[13], S44, 0x4e0811a1);
  II ( a, b, c, d, block[ 4], S41, 0xf7537e82);
  II ( d, a, b, c, block[11], S42, 0xbd3af235);
  II ( c, d, a, b, block[ 2], S43, 0x2ad7d2bb);
  II ( b, c, d, a, block[ 9], S44, 0xeb86d391);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

// only use this when really, really needed, SLOW

void md5_complete_no_limit (uint digest[4], uint *plain, uint plain_len)
{
  uint a = MAGIC_A;
  uint b = MAGIC_B;
  uint c = MAGIC_C;
  uint d = MAGIC_D;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;

  uint r_a = digest[0];
  uint r_b = digest[1];
  uint r_c = digest[2];
  uint r_d = digest[3];

  uint block[16];
  int  block_total_len = 16 * 4; // sizeof (block)

  char *block_ptr = (char *) block;
  char *plain_ptr = (char *) plain;

  // init

  int remaining_len = plain_len;

  // loop

  uint loop = 1;

  while (loop)
  {
    loop = (remaining_len > 55);

    int cur_len  = MIN (block_total_len, remaining_len);
    int copy_len = MAX (cur_len, 0);  // should never be negative of course

    memcpy (block_ptr, plain_ptr, copy_len);

    // clear the remaining bytes of the block

    memset (block_ptr + copy_len, 0, block_total_len - copy_len);

    /*
     * final block
     */

    // set 0x80 if neeeded

    if (cur_len >= 0)
    {
      if (cur_len != block_total_len)
      {
        block_ptr[copy_len] = 0x80;
      }
    }

    // set block[14] set to total_len

    if (! loop) block[14] = plain_len * 8;

    /*
     * md5 ()
     */

    #define S11 7
    #define S12 12
    #define S13 17
    #define S14 22

    FF ( a, b, c, d, block[ 0], S11, 0xd76aa478);
    FF ( d, a, b, c, block[ 1], S12, 0xe8c7b756);
    FF ( c, d, a, b, block[ 2], S13, 0x242070db);
    FF ( b, c, d, a, block[ 3], S14, 0xc1bdceee);
    FF ( a, b, c, d, block[ 4], S11, 0xf57c0faf);
    FF ( d, a, b, c, block[ 5], S12, 0x4787c62a);
    FF ( c, d, a, b, block[ 6], S13, 0xa8304613);
    FF ( b, c, d, a, block[ 7], S14, 0xfd469501);
    FF ( a, b, c, d, block[ 8], S11, 0x698098d8);
    FF ( d, a, b, c, block[ 9], S12, 0x8b44f7af);
    FF ( c, d, a, b, block[10], S13, 0xffff5bb1);
    FF ( b, c, d, a, block[11], S14, 0x895cd7be);
    FF ( a, b, c, d, block[12], S11, 0x6b901122);
    FF ( d, a, b, c, block[13], S12, 0xfd987193);
    FF ( c, d, a, b, block[14], S13, 0xa679438e);
    FF ( b, c, d, a, block[15], S14, 0x49b40821);

    #define S21 5
    #define S22 9
    #define S23 14
    #define S24 20

    GG ( a, b, c, d, block[ 1], S21, 0xf61e2562);
    GG ( d, a, b, c, block[ 6], S22, 0xc040b340);
    GG ( c, d, a, b, block[11], S23, 0x265e5a51);
    GG ( b, c, d, a, block[ 0], S24, 0xe9b6c7aa);
    GG ( a, b, c, d, block[ 5], S21, 0xd62f105d);
    GG ( d, a, b, c, block[10], S22, 0x02441453);
    GG ( c, d, a, b, block[15], S23, 0xd8a1e681);
    GG ( b, c, d, a, block[ 4], S24, 0xe7d3fbc8);
    GG ( a, b, c, d, block[ 9], S21, 0x21e1cde6);
    GG ( d, a, b, c, block[14], S22, 0xc33707d6);
    GG ( c, d, a, b, block[ 3], S23, 0xf4d50d87);
    GG ( b, c, d, a, block[ 8], S24, 0x455a14ed);
    GG ( a, b, c, d, block[13], S21, 0xa9e3e905);
    GG ( d, a, b, c, block[ 2], S22, 0xfcefa3f8);
    GG ( c, d, a, b, block[ 7], S23, 0x676f02d9);
    GG ( b, c, d, a, block[12], S24, 0x8d2a4c8a);

    #define S31 4
    #define S32 11
    #define S33 16
    #define S34 23

    HH ( a, b, c, d, block[ 5], S31, 0xfffa3942);
    HH ( d, a, b, c, block[ 8], S32, 0x8771f681);
    HH ( c, d, a, b, block[11], S33, 0x6d9d6122);
    HH ( b, c, d, a, block[14], S34, 0xfde5380c);
    HH ( a, b, c, d, block[ 1], S31, 0xa4beea44);
    HH ( d, a, b, c, block[ 4], S32, 0x4bdecfa9);
    HH ( c, d, a, b, block[ 7], S33, 0xf6bb4b60);
    HH ( b, c, d, a, block[10], S34, 0xbebfbc70);
    HH ( a, b, c, d, block[13], S31, 0x289b7ec6);
    HH ( d, a, b, c, block[ 0], S32, 0xeaa127fa);
    HH ( c, d, a, b, block[ 3], S33, 0xd4ef3085);
    HH ( b, c, d, a, block[ 6], S34, 0x04881d05);
    HH ( a, b, c, d, block[ 9], S31, 0xd9d4d039);
    HH ( d, a, b, c, block[12], S32, 0xe6db99e5);
    HH ( c, d, a, b, block[15], S33, 0x1fa27cf8);
    HH ( b, c, d, a, block[ 2], S34, 0xc4ac5665);

    #define S41 6
    #define S42 10
    #define S43 15
    #define S44 21

    II ( a, b, c, d, block[ 0], S41, 0xf4292244);
    II ( d, a, b, c, block[ 7], S42, 0x432aff97);
    II ( c, d, a, b, block[14], S43, 0xab9423a7);
    II ( b, c, d, a, block[ 5], S44, 0xfc93a039);
    II ( a, b, c, d, block[12], S41, 0x655b59c3);
    II ( d, a, b, c, block[ 3], S42, 0x8f0ccc92);
    II ( c, d, a, b, block[10], S43, 0xffeff47d);
    II ( b, c, d, a, block[ 1], S44, 0x85845dd1);
    II ( a, b, c, d, block[ 8], S41, 0x6fa87e4f);
    II ( d, a, b, c, block[15], S42, 0xfe2ce6e0);
    II ( c, d, a, b, block[ 6], S43, 0xa3014314);
    II ( b, c, d, a, block[13], S44, 0x4e0811a1);
    II ( a, b, c, d, block[ 4], S41, 0xf7537e82);
    II ( d, a, b, c, block[11], S42, 0xbd3af235);
    II ( c, d, a, b, block[ 2], S43, 0x2ad7d2bb);
    II ( b, c, d, a, block[ 9], S44, 0xeb86d391);

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
