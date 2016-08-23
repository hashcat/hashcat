#include <cpu/cpu-md5.h>
#include <bit_ops.h>

uint F(uint x, uint y, uint z);
inline uint F(uint x, uint y, uint z) {
  return (x& y) | (~x & z);
}

uint G(uint x, uint y, uint z);
inline uint G(uint x, uint y, uint z) {
  return ((x & z) | (y & ~z));
}

uint H(uint x, uint y, uint z);
inline uint H(uint x, uint y, uint z) {
  return (x ^ y ^ z);
}

uint I(uint x, uint y, uint z);
inline uint I(uint x, uint y, uint z) {
  return (y ^ (x | ~z));
}


uint FF(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac);
inline uint FF(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac) {
  a += F(b, c, d) + x + ac;
  a = rotl32(a, s);
  return a + b;
}

uint GG(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac);
inline uint GG(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac) {
  a += G(b, c, d) + x + ac;
  a = rotl32(a, s);
  return a + b;
}

uint HH(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac);
inline uint HH(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac) {
  a += H(b, c, d) + x + ac;
  a = rotl32(a, s);
  return a + b;
}

uint II(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac);
inline uint II(uint a, uint b, uint c, uint d, uint x, u8 s, uint ac) {
  a += I(b, c, d) + x + ac;
  a = rotl32(a, s);
  return a + b;
}

void md5_64(uint block[16], uint digest[4])
{
  uint a = digest[0];
  uint b = digest[1];
  uint c = digest[2];
  uint d = digest[3];

#define S1 7
#define S2 12
#define S3 17
#define S4 22

  a = FF(a, b, c, d, block[0], S1, 0xd76aa478);
  d = FF(d, a, b, c, block[1], S2, 0xe8c7b756);
  c = FF(c, d, a, b, block[2], S3, 0x242070db);
  b = FF(b, c, d, a, block[3], S4, 0xc1bdceee);
  a = FF(a, b, c, d, block[4], S1, 0xf57c0faf);
  d = FF(d, a, b, c, block[5], S2, 0x4787c62a);
  c = FF(c, d, a, b, block[6], S3, 0xa8304613);
  b = FF(b, c, d, a, block[7], S4, 0xfd469501);
  a = FF(a, b, c, d, block[8], S1, 0x698098d8);
  d = FF(d, a, b, c, block[9], S2, 0x8b44f7af);
  c = FF(c, d, a, b, block[10], S3, 0xffff5bb1);
  b = FF(b, c, d, a, block[11], S4, 0x895cd7be);
  a = FF(a, b, c, d, block[12], S1, 0x6b901122);
  d = FF(d, a, b, c, block[13], S2, 0xfd987193);
  c = FF(c, d, a, b, block[14], S3, 0xa679438e);
  b = FF(b, c, d, a, block[15], S4, 0x49b40821);

#define S1 5
#define S2 9
#define S3 14
#define S4 20

  a = GG(a, b, c, d, block[1], S1, 0xf61e2562);
  d = GG(d, a, b, c, block[6], S2, 0xc040b340);
  c = GG(c, d, a, b, block[11], S3, 0x265e5a51);
  b = GG(b, c, d, a, block[0], S4, 0xe9b6c7aa);
  a = GG(a, b, c, d, block[5], S1, 0xd62f105d);
  d = GG(d, a, b, c, block[10], S2, 0x02441453);
  c = GG(c, d, a, b, block[15], S3, 0xd8a1e681);
  b = GG(b, c, d, a, block[4], S4, 0xe7d3fbc8);
  a = GG(a, b, c, d, block[9], S1, 0x21e1cde6);
  d = GG(d, a, b, c, block[14], S2, 0xc33707d6);
  c = GG(c, d, a, b, block[3], S3, 0xf4d50d87);
  b = GG(b, c, d, a, block[8], S4, 0x455a14ed);
  a = GG(a, b, c, d, block[13], S1, 0xa9e3e905);
  d = GG(d, a, b, c, block[2], S2, 0xfcefa3f8);
  c = GG(c, d, a, b, block[7], S3, 0x676f02d9);
  b = GG(b, c, d, a, block[12], S4, 0x8d2a4c8a);

#define S1 4
#define S2 11
#define S3 16
#define S4 23

  a = HH(a, b, c, d, block[5], S1, 0xfffa3942);
  d = HH(d, a, b, c, block[8], S2, 0x8771f681);
  c = HH(c, d, a, b, block[11], S3, 0x6d9d6122);
  b = HH(b, c, d, a, block[14], S4, 0xfde5380c);
  a = HH(a, b, c, d, block[1], S1, 0xa4beea44);
  d = HH(d, a, b, c, block[4], S2, 0x4bdecfa9);
  c = HH(c, d, a, b, block[7], S3, 0xf6bb4b60);
  b = HH(b, c, d, a, block[10], S4, 0xbebfbc70);
  a = HH(a, b, c, d, block[13], S1, 0x289b7ec6);
  d = HH(d, a, b, c, block[0], S2, 0xeaa127fa);
  c = HH(c, d, a, b, block[3], S3, 0xd4ef3085);
  b = HH(b, c, d, a, block[6], S4, 0x04881d05);
  a = HH(a, b, c, d, block[9], S1, 0xd9d4d039);
  d = HH(d, a, b, c, block[12], S2, 0xe6db99e5);
  c = HH(c, d, a, b, block[15], S3, 0x1fa27cf8);
  b = HH(b, c, d, a, block[2], S4, 0xc4ac5665);

#define S1 6
#define S2 10
#define S3 15
#define S4 21

  a = II(a, b, c, d, block[0], S1, 0xf4292244);
  d = II(d, a, b, c, block[7], S2, 0x432aff97);
  c = II(c, d, a, b, block[14], S3, 0xab9423a7);
  b = II(b, c, d, a, block[5], S4, 0xfc93a039);
  a = II(a, b, c, d, block[12], S1, 0x655b59c3);
  d = II(d, a, b, c, block[3], S2, 0x8f0ccc92);
  c = II(c, d, a, b, block[10], S3, 0xffeff47d);
  b = II(b, c, d, a, block[1], S4, 0x85845dd1);
  a = II(a, b, c, d, block[8], S1, 0x6fa87e4f);
  d = II(d, a, b, c, block[15], S2, 0xfe2ce6e0);
  c = II(c, d, a, b, block[6], S3, 0xa3014314);
  b = II(b, c, d, a, block[13], S4, 0x4e0811a1);
  a = II(a, b, c, d, block[4], S1, 0xf7537e82);
  d = II(d, a, b, c, block[11], S2, 0xbd3af235);
  c = II(c, d, a, b, block[2], S3, 0x2ad7d2bb);
  b = II(b, c, d, a, block[9], S4, 0xeb86d391);

#undef S1
#undef S2
#undef S3
#undef S4

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

// only use this when really, really needed, SLOW

void md5_complete_no_limit(uint digest[4], uint *plain, uint plain_len)
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

  char *block_ptr = (char *)block;
  char *plain_ptr = (char *)plain;

  // init

  int remaining_len = plain_len;

  // loop

  uint loop = 1;

  while (loop)
  {
    loop = (remaining_len > 55);

    int cur_len = __max(block_total_len, remaining_len);
    int copy_len = __max(cur_len, 0);  // should never be negative of course

    memcpy(block_ptr, plain_ptr, copy_len);

    // clear the remaining bytes of the block

    memset(block_ptr + copy_len, 0, block_total_len - copy_len);

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

    if (!loop) block[14] = plain_len * 8;

    /*
    * md5 ()
    */

#define S1 7
#define S2 12
#define S3 17
#define S4 22

    a = FF(a, b, c, d, block[0], S1, 0xd76aa478);
    d = FF(d, a, b, c, block[1], S2, 0xe8c7b756);
    c = FF(c, d, a, b, block[2], S3, 0x242070db);
    b = FF(b, c, d, a, block[3], S4, 0xc1bdceee);
    a = FF(a, b, c, d, block[4], S1, 0xf57c0faf);
    d = FF(d, a, b, c, block[5], S2, 0x4787c62a);
    c = FF(c, d, a, b, block[6], S3, 0xa8304613);
    b = FF(b, c, d, a, block[7], S4, 0xfd469501);
    a = FF(a, b, c, d, block[8], S1, 0x698098d8);
    d = FF(d, a, b, c, block[9], S2, 0x8b44f7af);
    c = FF(c, d, a, b, block[10], S3, 0xffff5bb1);
    b = FF(b, c, d, a, block[11], S4, 0x895cd7be);
    a = FF(a, b, c, d, block[12], S1, 0x6b901122);
    d = FF(d, a, b, c, block[13], S2, 0xfd987193);
    c = FF(c, d, a, b, block[14], S3, 0xa679438e);
    b = FF(b, c, d, a, block[15], S4, 0x49b40821);

#define S1 5
#define S2 9
#define S3 14
#define S4 20

    a = GG(a, b, c, d, block[1], S1, 0xf61e2562);
    d = GG(d, a, b, c, block[6], S2, 0xc040b340);
    c = GG(c, d, a, b, block[11], S3, 0x265e5a51);
    b = GG(b, c, d, a, block[0], S4, 0xe9b6c7aa);
    a = GG(a, b, c, d, block[5], S1, 0xd62f105d);
    d = GG(d, a, b, c, block[10], S2, 0x02441453);
    c = GG(c, d, a, b, block[15], S3, 0xd8a1e681);
    b = GG(b, c, d, a, block[4], S4, 0xe7d3fbc8);
    a = GG(a, b, c, d, block[9], S1, 0x21e1cde6);
    d = GG(d, a, b, c, block[14], S2, 0xc33707d6);
    c = GG(c, d, a, b, block[3], S3, 0xf4d50d87);
    b = GG(b, c, d, a, block[8], S4, 0x455a14ed);
    a = GG(a, b, c, d, block[13], S1, 0xa9e3e905);
    d = GG(d, a, b, c, block[2], S2, 0xfcefa3f8);
    c = GG(c, d, a, b, block[7], S3, 0x676f02d9);
    b = GG(b, c, d, a, block[12], S4, 0x8d2a4c8a);

#define S1 4
#define S2 11
#define S3 16
#define S4 23

    a = HH(a, b, c, d, block[5], S1, 0xfffa3942);
    d = HH(d, a, b, c, block[8], S2, 0x8771f681);
    c = HH(c, d, a, b, block[11], S3, 0x6d9d6122);
    b = HH(b, c, d, a, block[14], S4, 0xfde5380c);
    a = HH(a, b, c, d, block[1], S1, 0xa4beea44);
    d = HH(d, a, b, c, block[4], S2, 0x4bdecfa9);
    c = HH(c, d, a, b, block[7], S3, 0xf6bb4b60);
    b = HH(b, c, d, a, block[10], S4, 0xbebfbc70);
    a = HH(a, b, c, d, block[13], S1, 0x289b7ec6);
    d = HH(d, a, b, c, block[0], S2, 0xeaa127fa);
    c = HH(c, d, a, b, block[3], S3, 0xd4ef3085);
    b = HH(b, c, d, a, block[6], S4, 0x04881d05);
    a = HH(a, b, c, d, block[9], S1, 0xd9d4d039);
    d = HH(d, a, b, c, block[12], S2, 0xe6db99e5);
    c = HH(c, d, a, b, block[15], S3, 0x1fa27cf8);
    b = HH(b, c, d, a, block[2], S4, 0xc4ac5665);

#define S1 6
#define S2 10
#define S3 15
#define S4 21

    a = II(a, b, c, d, block[0], S1, 0xf4292244);
    d = II(d, a, b, c, block[7], S2, 0x432aff97);
    c = II(c, d, a, b, block[14], S3, 0xab9423a7);
    b = II(b, c, d, a, block[5], S4, 0xfc93a039);
    a = II(a, b, c, d, block[12], S1, 0x655b59c3);
    d = II(d, a, b, c, block[3], S2, 0x8f0ccc92);
    c = II(c, d, a, b, block[10], S3, 0xffeff47d);
    b = II(b, c, d, a, block[1], S4, 0x85845dd1);
    a = II(a, b, c, d, block[8], S1, 0x6fa87e4f);
    d = II(d, a, b, c, block[15], S2, 0xfe2ce6e0);
    c = II(c, d, a, b, block[6], S3, 0xa3014314);
    b = II(b, c, d, a, block[13], S4, 0x4e0811a1);
    a = II(a, b, c, d, block[4], S1, 0xf7537e82);
    d = II(d, a, b, c, block[11], S2, 0xbd3af235);
    c = II(c, d, a, b, block[2], S3, 0x2ad7d2bb);
    b = II(b, c, d, a, block[9], S4, 0xeb86d391);

    remaining_len -= block_total_len;

    plain_ptr += 64;

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

#undef S1
#undef S2
#undef S3
#undef S4

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
