/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SCRYPT_H
#define INC_HASH_SCRYPT_H

#define GET_SCRYPT_SZ(r,p) (128 * (r) * (p))
#define GET_STATE_SZ(r)    (128 * (r))

// _SZ is true sizes as bytes
#define SCRYPT_SZ  GET_SCRYPT_SZ (SCRYPT_R, SCRYPT_P)
#define STATE_SZ   GET_STATE_SZ  (SCRYPT_R)

// _CNT is size as whatever /X datatype
#define SCRYPT_CNT4  (SCRYPT_SZ / 4)
#define STATE_CNT4   (STATE_SZ  / 4)

// this would be uint4, feels more natural than 16
#define SCRYPT_CNT44 ((SCRYPT_SZ / 4) / 4)
#define STATE_CNT44  ((STATE_SZ  / 4) / 4)

#define SALSA_SZ   64
#define SALSA_CNT4 (SALSA_SZ / 4)
#define SALSA_CNT44 ((SALSA_SZ / 4) / 4)

//#define VIDX(bid4,lsz,lid,ySIZE,zSIZE,y,z) (((bid4) * (lsz) * (ySIZE) * (zSIZE)) + ((lid) * (ySIZE) * (zSIZE)) + ((y) * (zSIZE)) + (z))

#if defined IS_CUDA

DECLSPEC uint4 operator ^ (const uint4 a, const uint4 b)
{
  uint4 r;

  r.x = a.x ^ b.x;
  r.y = a.y ^ b.y;
  r.z = a.z ^ b.z;
  r.w = a.w ^ b.w;

  return r;
}

#endif

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  u32 in[SCRYPT_TMP_ELEM / 2];
  u32 out[SCRYPT_TMP_ELEM / 2];

} scrypt_tmp_t;

#endif
