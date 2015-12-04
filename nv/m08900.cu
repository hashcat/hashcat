/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SCRYPT_

#include "include/constants.h"
#include "include/kernel_vendor.h"

#ifdef  VLIW1
#define VECT_SIZE1
#endif

#ifdef  VLIW2
#define VECT_SIZE1
#endif

#define DGST_R0 0
#define DGST_R1 1
#define DGST_R2 2
#define DGST_R3 3

#include "include/kernel_functions.c"
#include "types_nv.c"
#include "common_nv.c"

#ifdef  VECT_SIZE1
#define VECT_COMPARE_M "check_multi_vect1_comp4.c"
#endif

#ifdef  VECT_SIZE2
#define VECT_COMPARE_M "check_multi_vect2_comp4.c"
#endif

#ifdef  VECT_SIZE4
#define VECT_COMPARE_M "check_multi_vect4_comp4.c"
#endif

class uintm
{
  private:
  public:

  u32 x;
  u32 y;
  u32 z;
  u32 w;

    inline __device__  uintm (const u32 a, const u32 b, const u32 c, const u32 d) : x(a), y(b), z(c), w(d) { }
    inline __device__  uintm (const u32 a)                                           : x(a), y(a), z(a), w(a) { }

    inline __device__  uintm (void) { }
    inline __device__ ~uintm (void) { }
};

typedef struct
{
  uintm P[64];

} scrypt_tmp_t;

__device__ static uintm __byte_perm (const uintm a, const uintm b, const u32 c)
{
  return uintm (__byte_perm (a.x, b.x, c),
                __byte_perm (a.y, b.y, c),
                __byte_perm (a.z, b.z, c),
                __byte_perm (a.w, b.w, c));
}

__device__ static uintm rotate (const uintm a, const unsigned int n)
{
  return uintm  (rotl32 (a.x, n),
                 rotl32 (a.y, n),
                 rotl32 (a.z, n),
                 rotl32 (a.w, n));
}

inline __device__ uintm wxyz (const uintm a) { return uintm (a.w, a.x, a.y, a.z); }
inline __device__ uintm zwxy (const uintm a) { return uintm (a.z, a.w, a.x, a.y); }

inline __device__ uintm operator << (const uintm  a, const u32  b) { return uintm ((a.x << b  ), (a.y << b  ), (a.z << b  ), (a.w << b  ));  }
inline __device__ uintm operator << (const uintm  a, const uintm b) { return uintm ((a.x << b.x), (a.y << b.y), (a.z << b.z), (a.w << b.w));  }

inline __device__ uintm operator >> (const uintm  a, const u32  b) { return uintm ((a.x >> b  ), (a.y >> b  ), (a.z >> b  ), (a.w >> b  ));  }
inline __device__ uintm operator >> (const uintm  a, const uintm b) { return uintm ((a.x >> b.x), (a.y >> b.y), (a.z >> b.z), (a.w >> b.w));  }

inline __device__ uintm operator ^  (const uintm  a, const u32  b) { return uintm ((a.x ^  b  ), (a.y ^  b  ), (a.z ^  b  ), (a.w ^  b  ));  }
inline __device__ uintm operator ^  (const uintm  a, const uintm b) { return uintm ((a.x ^  b.x), (a.y ^  b.y), (a.z ^  b.z), (a.w ^  b.w));  }

inline __device__ uintm operator |  (const uintm  a, const u32  b) { return uintm ((a.x |  b  ), (a.y |  b  ), (a.z |  b  ), (a.w |  b  ));  }
inline __device__ uintm operator |  (const uintm  a, const uintm b) { return uintm ((a.x |  b.x), (a.y |  b.y), (a.z |  b.z), (a.w |  b.w));  }

inline __device__ uintm operator &  (const uintm  a, const u32  b) { return uintm ((a.x &  b  ), (a.y &  b  ), (a.z &  b  ), (a.w &  b  ));  }
inline __device__ uintm operator &  (const uintm  a, const uintm b) { return uintm ((a.x &  b.x), (a.y &  b.y), (a.z &  b.z), (a.w &  b.w));  }

inline __device__ uintm operator +  (const uintm  a, const u32  b) { return uintm ((a.x +  b  ), (a.y +  b  ), (a.z +  b  ), (a.w +  b  ));  }
inline __device__ uintm operator +  (const uintm  a, const uintm b) { return uintm ((a.x +  b.x), (a.y +  b.y), (a.z +  b.z), (a.w +  b.w));  }

inline __device__ void  operator ^= (uintm &a, const u32  b) { a.x ^= b;   a.y ^= b;   a.z ^= b;   a.w ^= b;   }
inline __device__ void  operator ^= (uintm &a, const uintm b) { a.x ^= b.x; a.y ^= b.y; a.z ^= b.z; a.w ^= b.w; }

inline __device__ void  operator += (uintm &a, const u32  b) { a.x += b;   a.y += b;   a.z += b;   a.w += b;   }
inline __device__ void  operator += (uintm &a, const uintm b) { a.x += b.x; a.y += b.y; a.z += b.z; a.w += b.w; }

__constant__ u32 k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

__device__ static void sha256_transform (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[8])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
  }

  ROUND_STEP (0);

  for (int i = 16; i < 64; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

__device__ static void hmac_sha256_pad (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[8], u32x opad[8])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA256M_A;
  ipad[1] = SHA256M_B;
  ipad[2] = SHA256M_C;
  ipad[3] = SHA256M_D;
  ipad[4] = SHA256M_E;
  ipad[5] = SHA256M_F;
  ipad[6] = SHA256M_G;
  ipad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA256M_A;
  opad[1] = SHA256M_B;
  opad[2] = SHA256M_C;
  opad[3] = SHA256M_D;
  opad[4] = SHA256M_E;
  opad[5] = SHA256M_F;
  opad[6] = SHA256M_G;
  opad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, opad);
}

__device__ static void hmac_sha256_run (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[8], u32x opad[8], u32x digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform (w0, w1, w2, w3, digest);
}

__device__ static void memcat8 (u32x block0[4], u32x block1[4], u32x block2[4], u32x block3[4], const u32 block_len, const u32 append[2])
{
  switch (block_len)
  {
    case 0:
      block0[0] = append[0];
      block0[1] = append[1];
      break;

    case 1:
      block0[0] = block0[0]       | append[0] <<  8;
      block0[1] = append[0] >> 24 | append[1] <<  8;
      block0[2] = append[1] >> 24;
      break;

    case 2:
      block0[0] = block0[0]       | append[0] << 16;
      block0[1] = append[0] >> 16 | append[1] << 16;
      block0[2] = append[1] >> 16;
      break;

    case 3:
      block0[0] = block0[0]       | append[0] << 24;
      block0[1] = append[0] >>  8 | append[1] << 24;
      block0[2] = append[1] >>  8;
      break;

    case 4:
      block0[1] = append[0];
      block0[2] = append[1];
      break;

    case 5:
      block0[1] = block0[1]       | append[0] <<  8;
      block0[2] = append[0] >> 24 | append[1] <<  8;
      block0[3] = append[1] >> 24;
      break;

    case 6:
      block0[1] = block0[1]       | append[0] << 16;
      block0[2] = append[0] >> 16 | append[1] << 16;
      block0[3] = append[1] >> 16;
      break;

    case 7:
      block0[1] = block0[1]       | append[0] << 24;
      block0[2] = append[0] >>  8 | append[1] << 24;
      block0[3] = append[1] >>  8;
      break;

    case 8:
      block0[2] = append[0];
      block0[3] = append[1];
      break;

    case 9:
      block0[2] = block0[2]       | append[0] <<  8;
      block0[3] = append[0] >> 24 | append[1] <<  8;
      block1[0] = append[1] >> 24;
      break;

    case 10:
      block0[2] = block0[2]       | append[0] << 16;
      block0[3] = append[0] >> 16 | append[1] << 16;
      block1[0] = append[1] >> 16;
      break;

    case 11:
      block0[2] = block0[2]       | append[0] << 24;
      block0[3] = append[0] >>  8 | append[1] << 24;
      block1[0] = append[1] >>  8;
      break;

    case 12:
      block0[3] = append[0];
      block1[0] = append[1];
      break;

    case 13:
      block0[3] = block0[3]       | append[0] <<  8;
      block1[0] = append[0] >> 24 | append[1] <<  8;
      block1[1] = append[1] >> 24;
      break;

    case 14:
      block0[3] = block0[3]       | append[0] << 16;
      block1[0] = append[0] >> 16 | append[1] << 16;
      block1[1] = append[1] >> 16;
      break;

    case 15:
      block0[3] = block0[3]       | append[0] << 24;
      block1[0] = append[0] >>  8 | append[1] << 24;
      block1[1] = append[1] >>  8;
      break;

    case 16:
      block1[0] = append[0];
      block1[1] = append[1];
      break;

    case 17:
      block1[0] = block1[0]       | append[0] <<  8;
      block1[1] = append[0] >> 24 | append[1] <<  8;
      block1[2] = append[1] >> 24;
      break;

    case 18:
      block1[0] = block1[0]       | append[0] << 16;
      block1[1] = append[0] >> 16 | append[1] << 16;
      block1[2] = append[1] >> 16;
      break;

    case 19:
      block1[0] = block1[0]       | append[0] << 24;
      block1[1] = append[0] >>  8 | append[1] << 24;
      block1[2] = append[1] >>  8;
      break;

    case 20:
      block1[1] = append[0];
      block1[2] = append[1];
      break;

    case 21:
      block1[1] = block1[1]       | append[0] <<  8;
      block1[2] = append[0] >> 24 | append[1] <<  8;
      block1[3] = append[1] >> 24;
      break;

    case 22:
      block1[1] = block1[1]       | append[0] << 16;
      block1[2] = append[0] >> 16 | append[1] << 16;
      block1[3] = append[1] >> 16;
      break;

    case 23:
      block1[1] = block1[1]       | append[0] << 24;
      block1[2] = append[0] >>  8 | append[1] << 24;
      block1[3] = append[1] >>  8;
      break;

    case 24:
      block1[2] = append[0];
      block1[3] = append[1];
      break;

    case 25:
      block1[2] = block1[2]       | append[0] <<  8;
      block1[3] = append[0] >> 24 | append[1] <<  8;
      block2[0] = append[1] >> 24;
      break;

    case 26:
      block1[2] = block1[2]       | append[0] << 16;
      block1[3] = append[0] >> 16 | append[1] << 16;
      block2[0] = append[1] >> 16;
      break;

    case 27:
      block1[2] = block1[2]       | append[0] << 24;
      block1[3] = append[0] >>  8 | append[1] << 24;
      block2[0] = append[1] >>  8;
      break;

    case 28:
      block1[3] = append[0];
      block2[0] = append[1];
      break;

    case 29:
      block1[3] = block1[3]       | append[0] <<  8;
      block2[0] = append[0] >> 24 | append[1] <<  8;
      block2[1] = append[1] >> 24;
      break;

    case 30:
      block1[3] = block1[3]       | append[0] << 16;
      block2[0] = append[0] >> 16 | append[1] << 16;
      block2[1] = append[1] >> 16;
      break;

    case 31:
      block1[3] = block1[3]       | append[0] << 24;
      block2[0] = append[0] >>  8 | append[1] << 24;
      block2[1] = append[1] >>  8;
      break;

    case 32:
      block2[0] = append[0];
      block2[1] = append[1];
      break;

    case 33:
      block2[0] = block2[0]       | append[0] <<  8;
      block2[1] = append[0] >> 24 | append[1] <<  8;
      block2[2] = append[1] >> 24;
      break;

    case 34:
      block2[0] = block2[0]       | append[0] << 16;
      block2[1] = append[0] >> 16 | append[1] << 16;
      block2[2] = append[1] >> 16;
      break;

    case 35:
      block2[0] = block2[0]       | append[0] << 24;
      block2[1] = append[0] >>  8 | append[1] << 24;
      block2[2] = append[1] >>  8;
      break;

    case 36:
      block2[1] = append[0];
      block2[2] = append[1];
      break;

    case 37:
      block2[1] = block2[1]       | append[0] <<  8;
      block2[2] = append[0] >> 24 | append[1] <<  8;
      block2[3] = append[1] >> 24;
      break;

    case 38:
      block2[1] = block2[1]       | append[0] << 16;
      block2[2] = append[0] >> 16 | append[1] << 16;
      block2[3] = append[1] >> 16;
      break;

    case 39:
      block2[1] = block2[1]       | append[0] << 24;
      block2[2] = append[0] >>  8 | append[1] << 24;
      block2[3] = append[1] >>  8;
      break;

    case 40:
      block2[2] = append[0];
      block2[3] = append[1];
      break;

    case 41:
      block2[2] = block2[2]       | append[0] <<  8;
      block2[3] = append[0] >> 24 | append[1] <<  8;
      block3[0] = append[1] >> 24;
      break;

    case 42:
      block2[2] = block2[2]       | append[0] << 16;
      block2[3] = append[0] >> 16 | append[1] << 16;
      block3[0] = append[1] >> 16;
      break;

    case 43:
      block2[2] = block2[2]       | append[0] << 24;
      block2[3] = append[0] >>  8 | append[1] << 24;
      block3[0] = append[1] >>  8;
      break;

    case 44:
      block2[3] = append[0];
      block3[0] = append[1];
      break;

    case 45:
      block2[3] = block2[3]       | append[0] <<  8;
      block3[0] = append[0] >> 24 | append[1] <<  8;
      block3[1] = append[1] >> 24;
      break;

    case 46:
      block2[3] = block2[3]       | append[0] << 16;
      block3[0] = append[0] >> 16 | append[1] << 16;
      block3[1] = append[1] >> 16;
      break;

    case 47:
      block2[3] = block2[3]       | append[0] << 24;
      block3[0] = append[0] >>  8 | append[1] << 24;
      block3[1] = append[1] >>  8;
      break;

    case 48:
      block3[0] = append[0];
      block3[1] = append[1];
      break;

    case 49:
      block3[0] = block3[0]       | append[0] <<  8;
      block3[1] = append[0] >> 24 | append[1] <<  8;
      block3[2] = append[1] >> 24;
      break;

    case 50:
      block3[0] = block3[0]       | append[0] << 16;
      block3[1] = append[0] >> 16 | append[1] << 16;
      block3[2] = append[1] >> 16;
      break;

    case 51:
      block3[0] = block3[0]       | append[0] << 24;
      block3[1] = append[0] >>  8 | append[1] << 24;
      block3[2] = append[1] >>  8;
      break;

    case 52:
      block3[1] = append[0];
      block3[2] = append[1];
      break;

    case 53:
      block3[1] = block3[1]       | append[0] <<  8;
      block3[2] = append[0] >> 24 | append[1] <<  8;
      block3[3] = append[1] >> 24;
      break;

    case 54:
      block3[1] = block3[1]       | append[0] << 16;
      block3[2] = append[0] >> 16 | append[1] << 16;
      block3[3] = append[1] >> 16;
      break;

    case 55:
      block3[1] = block3[1]       | append[0] << 24;
      block3[2] = append[0] >>  8 | append[1] << 24;
      block3[3] = append[1] >>  8;
      break;

    case 56:
      block3[2] = append[0];
      block3[3] = append[1];
      break;
  }
}

__device__ static uintm swap_workaround (uintm v)
{
  return __byte_perm (v, 0, 0x0123);
}

#define GET_SCRYPT_CNT(r,p) (2 * (r) * 16 * (p))
#define GET_SMIX_CNT(r,N)   (2 * (r) * 16 * (N))
#define GET_STATE_CNT(r)    (2 * (r) * 16)

#define ADD_ROTATE_XOR(r,i1,i2,s) (r) ^= rotate ((i1) + (i2), (s));

#define SALSA20_2R()                    \
{                                       \
  ADD_ROTATE_XOR (X1, X0, X3,  7);      \
  ADD_ROTATE_XOR (X2, X1, X0,  9);      \
  ADD_ROTATE_XOR (X3, X2, X1, 13);      \
  ADD_ROTATE_XOR (X0, X3, X2, 18);      \
                                        \
  X1 = uintm (X1.w, X1.x, X1.y, X1.z);  \
  X2 = uintm (X2.z, X2.w, X2.x, X2.y);  \
  X3 = uintm (X3.y, X3.z, X3.w, X3.x);  \
                                        \
  ADD_ROTATE_XOR (X3, X0, X1,  7);      \
  ADD_ROTATE_XOR (X2, X3, X0,  9);      \
  ADD_ROTATE_XOR (X1, X2, X3, 13);      \
  ADD_ROTATE_XOR (X0, X1, X2, 18);      \
                                        \
  X1 = uintm (X1.y, X1.z, X1.w, X1.x);  \
  X2 = uintm (X2.z, X2.w, X2.x, X2.y);  \
  X3 = uintm (X3.w, X3.x, X3.y, X3.z);  \
}

#define SALSA20_8_XOR() \
{                       \
  R0 = R0 ^ Y0;         \
  R1 = R1 ^ Y1;         \
  R2 = R2 ^ Y2;         \
  R3 = R3 ^ Y3;         \
                        \
  uintm X0 = R0;        \
  uintm X1 = R1;        \
  uintm X2 = R2;        \
  uintm X3 = R3;        \
                        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
                        \
  R0 = R0 + X0;         \
  R1 = R1 + X1;         \
  R2 = R2 + X2;         \
  R3 = R3 + X3;         \
}

__device__ static void salsa_r (uintm T[8], const u32 r)
{
  const u32 state_cnt = GET_STATE_CNT (r);

  const u32 state_cnt4 = state_cnt / 4;

  uintm R0 = T[state_cnt4 - 4];
  uintm R1 = T[state_cnt4 - 3];
  uintm R2 = T[state_cnt4 - 2];
  uintm R3 = T[state_cnt4 - 1];

  for (u32 i = 0; i < state_cnt4; i += 8)
  {
    uintm Y0;
    uintm Y1;
    uintm Y2;
    uintm Y3;

    Y0 = T[i + 0];
    Y1 = T[i + 1];
    Y2 = T[i + 2];
    Y3 = T[i + 3];

    SALSA20_8_XOR ();

    T[i + 0] = R0;
    T[i + 1] = R1;
    T[i + 2] = R2;
    T[i + 3] = R3;

    Y0 = T[i + 4];
    Y1 = T[i + 5];
    Y2 = T[i + 6];
    Y3 = T[i + 7];

    SALSA20_8_XOR ();

    T[i + 4] = R0;
    T[i + 5] = R1;
    T[i + 6] = R2;
    T[i + 7] = R3;
  }

  #define exchg(x,y) { const uintm t = T[(x)]; T[(x)] = T[(y)]; T[(y)] = t; }

  #define exchg4(x,y)         \
  {                           \
    const u32 x4 = (x) * 4;  \
    const u32 y4 = (y) * 4;  \
                              \
    exchg (x4 + 0, y4 + 0);   \
    exchg (x4 + 1, y4 + 1);   \
    exchg (x4 + 2, y4 + 2);   \
    exchg (x4 + 3, y4 + 3);   \
  }

  for (u32 i = 1; i < r / 1; i++)
  {
    const u32 x = i * 1;
    const u32 y = i * 2;

    exchg4 (x, y);
  }

  for (u32 i = 1; i < r / 2; i++)
  {
    const u32 x = i * 1;
    const u32 y = i * 2;

    const u32 xr1 = (r * 2) - 1 - x;
    const u32 yr1 = (r * 2) - 1 - y;

    exchg4 (xr1, yr1);
  }
}

__device__ static void scrypt_smix (uintm *X, uintm *T, const u32 N, const u32 r, const u32 tmto, const u32 phy, uintm *V)
{
  const u32 state_cnt = GET_STATE_CNT (r);

  const u32 state_cnt4 = state_cnt / 4;

  #if __CUDA_ARCH__ >= 500
  #define Coord(x,y,z) (((y) * zSIZE) + ((x) * zSIZE * ySIZE) + (z))
  #define CO Coord(x,y,z)
  #else
  #define Coord(x,y,z) (((x) * zSIZE) + ((y) * zSIZE * xSIZE) + (z))
  #define CO Coord(x,y,z)
  #endif

  const u32 xSIZE = phy;
  const u32 ySIZE = N / tmto;
  const u32 zSIZE = state_cnt4;

  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  const u32 x = gid % xSIZE;

  for (u32 i = 0; i < state_cnt4; i += 4)
  {
    T[0] = uintm (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = uintm (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = uintm (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = uintm (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }

  for (u32 y = 0; y < ySIZE; y++)
  {
    for (u32 z = 0; z < zSIZE; z++) V[CO] = X[z];

    for (u32 i = 0; i < tmto; i++) salsa_r (X, r);
  }

  for (u32 i = 0; i < N; i++)
  {
    const u32 k = X[zSIZE - 4].x & (N - 1);

    const u32 y = k / tmto;

    const u32 km = k - (y * tmto);

    for (u32 z = 0; z < zSIZE; z++) T[z] = V[CO];

    for (u32 i = 0; i < km; i++) salsa_r (T, r);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r (X, r);
  }

  for (u32 i = 0; i < state_cnt4; i += 4)
  {
    T[0] = uintm (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = uintm (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = uintm (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = uintm (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }
}

extern "C" __global__ void __launch_bounds__ (64, 1) m08900_init (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, scrypt_tmp_t *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, uintm *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  u32x w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32x w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32x w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32x w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * memory buffers
   */

  const u32 scrypt_r = SCRYPT_R;
  const u32 scrypt_p = SCRYPT_P;
  //const u32 scrypt_N = SCRYPT_N;

  //const u32 state_cnt  = GET_STATE_CNT  (scrypt_r);
  const u32 scrypt_cnt = GET_SCRYPT_CNT (scrypt_r, scrypt_p);
  //const u32 smix_cnt   = GET_SMIX_CNT   (scrypt_r, scrypt_N);

  /**
   * 1st pbkdf2, creates B
   */

  w0[0] = swap_workaround (w0[0]);
  w0[1] = swap_workaround (w0[1]);
  w0[2] = swap_workaround (w0[2]);
  w0[3] = swap_workaround (w0[3]);
  w1[0] = swap_workaround (w1[0]);
  w1[1] = swap_workaround (w1[1]);
  w1[2] = swap_workaround (w1[2]);
  w1[3] = swap_workaround (w1[3]);
  w2[0] = swap_workaround (w2[0]);
  w2[1] = swap_workaround (w2[1]);
  w2[2] = swap_workaround (w2[2]);
  w2[3] = swap_workaround (w2[3]);
  w3[0] = swap_workaround (w3[0]);
  w3[1] = swap_workaround (w3[1]);
  w3[2] = swap_workaround (w3[2]);
  w3[3] = swap_workaround (w3[3]);

  u32 ipad[8];
  u32 opad[8];

  hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

  for (u32 i = 0, j = 0, k = 0; i < scrypt_cnt; i += 8, j += 1, k += 2)
  {
    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    u32 append[2];

    append[0] = swap_workaround (j + 1);
    append[1] = 0x80;

    memcat8 (w0, w1, w2, w3, salt_len, append);

    w0[0] = swap_workaround (w0[0]);
    w0[1] = swap_workaround (w0[1]);
    w0[2] = swap_workaround (w0[2]);
    w0[3] = swap_workaround (w0[3]);
    w1[0] = swap_workaround (w1[0]);
    w1[1] = swap_workaround (w1[1]);
    w1[2] = swap_workaround (w1[2]);
    w1[3] = swap_workaround (w1[3]);
    w2[0] = swap_workaround (w2[0]);
    w2[1] = swap_workaround (w2[1]);
    w2[2] = swap_workaround (w2[2]);
    w2[3] = swap_workaround (w2[3]);
    w3[0] = swap_workaround (w3[0]);
    w3[1] = swap_workaround (w3[1]);
    w3[2] = 0;
    w3[3] = (64 + salt_len + 4) * 8;

    u32x digest[8];

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    const uintm tmp0 = uintm (digest[0], digest[1], digest[2], digest[3]);
    const uintm tmp1 = uintm (digest[4], digest[5], digest[6], digest[7]);

    __syncthreads ();

    tmps[gid].P[k + 0] = tmp0;
    tmps[gid].P[k + 1] = tmp1;
  }
}

extern "C" __global__ void __launch_bounds__ (64, 1) m08900_loop (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, scrypt_tmp_t *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, uintm *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  const u32 scrypt_phy   = salt_bufs[salt_pos].scrypt_phy;

  const u32 state_cnt    = GET_STATE_CNT  (SCRYPT_R);
  const u32 scrypt_cnt   = GET_SCRYPT_CNT (SCRYPT_R, SCRYPT_P);

  const u32 state_cnt4   = state_cnt  / 4;
  const u32 scrypt_cnt4  = scrypt_cnt / 4;

  uintm X[state_cnt4];
  uintm T[state_cnt4];

  for (int z = 0; z < state_cnt4; z++) X[z] = swap_workaround (tmps[gid].P[z]);

  scrypt_smix (X, T, SCRYPT_N, SCRYPT_R, SCRYPT_TMTO, scrypt_phy, d_scryptV_buf);

  for (int z = 0; z < state_cnt4; z++) tmps[gid].P[z] = swap_workaround (X[z]);

  #if SCRYPT_P >= 1
  for (int i = state_cnt4; i < scrypt_cnt4; i += state_cnt4)
  {
    for (int z = 0; z < state_cnt4; z++) X[z] = swap_workaround (tmps[gid].P[i + z]);

    scrypt_smix (X, T, SCRYPT_N, SCRYPT_R, SCRYPT_TMTO, scrypt_phy, d_scryptV_buf);

    for (int z = 0; z < state_cnt4; z++) tmps[gid].P[i + z] = swap_workaround (X[z]);
  }
  #endif
}

extern "C" __global__ void __launch_bounds__ (64, 1) m08900_comp (const pw_t *pws, const gpu_rule_t *rules_buf, const comb_t *combs_buf, const bf_t *bfs_buf, scrypt_tmp_t *tmps, void *hooks, const u32 *bitmaps_buf_s1_a, const u32 *bitmaps_buf_s1_b, const u32 *bitmaps_buf_s1_c, const u32 *bitmaps_buf_s1_d, const u32 *bitmaps_buf_s2_a, const u32 *bitmaps_buf_s2_b, const u32 *bitmaps_buf_s2_c, const u32 *bitmaps_buf_s2_d, plain_t *plains_buf, const digest_t *digests_buf, u32 *hashes_shown, const salt_t *salt_bufs, const void *esalt_bufs, u32 *d_return_buf, uintm *d_scryptV_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;;
  const u32 lid = threadIdx.x;

  if (gid >= gid_max) return;

  u32x w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32x w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32x w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32x w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * memory buffers
   */

  const u32 scrypt_r = SCRYPT_R;
  const u32 scrypt_p = SCRYPT_P;

  const u32 scrypt_cnt = GET_SCRYPT_CNT (scrypt_r, scrypt_p);

  const u32 scrypt_cnt4  = scrypt_cnt / 4;

  /**
   * 2nd pbkdf2, creates B
   */

  w0[0] = swap_workaround (w0[0]);
  w0[1] = swap_workaround (w0[1]);
  w0[2] = swap_workaround (w0[2]);
  w0[3] = swap_workaround (w0[3]);
  w1[0] = swap_workaround (w1[0]);
  w1[1] = swap_workaround (w1[1]);
  w1[2] = swap_workaround (w1[2]);
  w1[3] = swap_workaround (w1[3]);
  w2[0] = swap_workaround (w2[0]);
  w2[1] = swap_workaround (w2[1]);
  w2[2] = swap_workaround (w2[2]);
  w2[3] = swap_workaround (w2[3]);
  w3[0] = swap_workaround (w3[0]);
  w3[1] = swap_workaround (w3[1]);
  w3[2] = swap_workaround (w3[2]);
  w3[3] = swap_workaround (w3[3]);

  u32 ipad[8];
  u32 opad[8];

  hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

  for (u32 l = 0; l < scrypt_cnt4; l += 4)
  {
    __syncthreads ();

    uintm tmp;

    tmp = tmps[gid].P[l + 0];

    w0[0] = tmp.x;
    w0[1] = tmp.y;
    w0[2] = tmp.z;
    w0[3] = tmp.w;

    tmp = tmps[gid].P[l + 1];

    w1[0] = tmp.x;
    w1[1] = tmp.y;
    w1[2] = tmp.z;
    w1[3] = tmp.w;

    tmp = tmps[gid].P[l + 2];

    w2[0] = tmp.x;
    w2[1] = tmp.y;
    w2[2] = tmp.z;
    w2[3] = tmp.w;

    tmp = tmps[gid].P[l + 3];

    w3[0] = tmp.x;
    w3[1] = tmp.y;
    w3[2] = tmp.z;
    w3[3] = tmp.w;

    sha256_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = 0x00000001;
  w0[1] = 0x80000000;
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
  w3[3] = (64 + (scrypt_cnt * 4) + 4) * 8;

  u32x digest[8];

  hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

  const u32x r0 = swap_workaround (digest[DGST_R0]);
  const u32x r1 = swap_workaround (digest[DGST_R1]);
  const u32x r2 = swap_workaround (digest[DGST_R2]);
  const u32x r3 = swap_workaround (digest[DGST_R3]);

  #define il_pos 0

  #include VECT_COMPARE_M
}
