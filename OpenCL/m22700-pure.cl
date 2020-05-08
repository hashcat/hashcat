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
#include "inc_cipher_aes.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

// fixed MultiBit salt (not a bug)

#define MULTIBIT_S0 0x35510380
#define MULTIBIT_S1 0x75a3b0c5

#define MULTIBIT_IV0 0x1f3944a3
#define MULTIBIT_IV1 0xb3118353
#define MULTIBIT_IV2 0x16865429
#define MULTIBIT_IV3 0x3e7289c4

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  uint4 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

DECLSPEC int is_valid_bitcoinj_8 (const u8 v)
{
  // .abcdefghijklmnopqrstuvwxyz

  if (v > (u8) 'z') return 0;
  if (v < (u8) '.') return 0;

  if ((v > (u8) '.') && (v < (u8) 'a')) return 0;

  return 1;
}

DECLSPEC int is_valid_bitcoinj (const u32 *w)
{
  if ((w[0] & 0x000000ff) != 0x0000000a) return 0;

  if ((w[0] & 0x0000ff00)  > 0x00007f00) return 0;

  // check for "org." substring:

  if ((w[0] & 0xffff0000) != 0x726f0000) return 0;
  if ((w[1] & 0x0000ffff) != 0x00002e67) return 0;

  if (is_valid_bitcoinj_8 (w[1] >> 16) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[1] >> 24) == 0) return 0;

  if (is_valid_bitcoinj_8 (w[2] >>  0) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >>  8) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >> 16) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[2] >> 24) == 0) return 0;

  if (is_valid_bitcoinj_8 (w[3] >>  0) == 0) return 0;
  if (is_valid_bitcoinj_8 (w[3] >>  8) == 0) return 0;

  return 1;
}

#ifdef IS_CUDA

inline __device__ uint4 operator &  (const uint4  a, const u32   b) { return make_uint4 ((a.x &  b  ), (a.y &  b  ), (a.z &  b  ), (a.w &  b  ));  }
inline __device__ uint4 operator << (const uint4  a, const u32   b) { return make_uint4 ((a.x << b  ), (a.y << b  ), (a.z << b  ), (a.w << b  ));  }
inline __device__ uint4 operator >> (const uint4  a, const u32   b) { return make_uint4 ((a.x >> b  ), (a.y >> b  ), (a.z >> b  ), (a.w >> b  ));  }
inline __device__ uint4 operator +  (const uint4  a, const uint4 b) { return make_uint4 ((a.x +  b.x), (a.y +  b.y), (a.z +  b.z), (a.w +  b.w));  }
inline __device__ uint4 operator ^  (const uint4  a, const uint4 b) { return make_uint4 ((a.x ^  b.x), (a.y ^  b.y), (a.z ^  b.z), (a.w ^  b.w));  }
inline __device__ uint4 operator |  (const uint4  a, const uint4 b) { return make_uint4 ((a.x |  b.x), (a.y |  b.y), (a.z |  b.z), (a.w |  b.w));  }
inline __device__ void  operator ^= (      uint4 &a, const uint4 b) {                     a.x ^= b.x;   a.y ^= b.y;   a.z ^= b.z;   a.w ^= b.w;    }

inline __device__ uint4 rotate (const uint4 a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}

#endif

DECLSPEC uint4 hc_swap32_4 (uint4 v)
{
  return (rotate ((v & 0x00FF00FF), 24u) | rotate ((v & 0xFF00FF00),  8u));
}

#define GET_SCRYPT_CNT(r,p) (2 * (r) * 16 * (p))
#define GET_SMIX_CNT(r,N)   (2 * (r) * 16 * (N))
#define GET_STATE_CNT(r)    (2 * (r) * 16)

#define SCRYPT_CNT  GET_SCRYPT_CNT (SCRYPT_R, SCRYPT_P)
#define SCRYPT_CNT4 (SCRYPT_CNT / 4)
#define STATE_CNT   GET_STATE_CNT  (SCRYPT_R)
#define STATE_CNT4  (STATE_CNT / 4)

#define ADD_ROTATE_XOR(r,i1,i2,s) (r) ^= rotate ((i1) + (i2), (s));

#ifdef IS_CUDA

#define SALSA20_2R()                        \
{                                           \
  ADD_ROTATE_XOR (X1, X0, X3,  7);          \
  ADD_ROTATE_XOR (X2, X1, X0,  9);          \
  ADD_ROTATE_XOR (X3, X2, X1, 13);          \
  ADD_ROTATE_XOR (X0, X3, X2, 18);          \
                                            \
  X1 = make_uint4 (X1.w, X1.x, X1.y, X1.z); \
  X2 = make_uint4 (X2.z, X2.w, X2.x, X2.y); \
  X3 = make_uint4 (X3.y, X3.z, X3.w, X3.x); \
                                            \
  ADD_ROTATE_XOR (X3, X0, X1,  7);          \
  ADD_ROTATE_XOR (X2, X3, X0,  9);          \
  ADD_ROTATE_XOR (X1, X2, X3, 13);          \
  ADD_ROTATE_XOR (X0, X1, X2, 18);          \
                                            \
  X1 = make_uint4 (X1.y, X1.z, X1.w, X1.x); \
  X2 = make_uint4 (X2.z, X2.w, X2.x, X2.y); \
  X3 = make_uint4 (X3.w, X3.x, X3.y, X3.z); \
}
#else
#define SALSA20_2R()                        \
{                                           \
  ADD_ROTATE_XOR (X1, X0, X3,  7);          \
  ADD_ROTATE_XOR (X2, X1, X0,  9);          \
  ADD_ROTATE_XOR (X3, X2, X1, 13);          \
  ADD_ROTATE_XOR (X0, X3, X2, 18);          \
                                            \
  X1 = X1.s3012;                            \
  X2 = X2.s2301;                            \
  X3 = X3.s1230;                            \
                                            \
  ADD_ROTATE_XOR (X3, X0, X1,  7);          \
  ADD_ROTATE_XOR (X2, X3, X0,  9);          \
  ADD_ROTATE_XOR (X1, X2, X3, 13);          \
  ADD_ROTATE_XOR (X0, X1, X2, 18);          \
                                            \
  X1 = X1.s1230;                            \
  X2 = X2.s2301;                            \
  X3 = X3.s3012;                            \
}
#endif

#define SALSA20_8_XOR() \
{                       \
  R0 = R0 ^ Y0;         \
  R1 = R1 ^ Y1;         \
  R2 = R2 ^ Y2;         \
  R3 = R3 ^ Y3;         \
                        \
  uint4 X0 = R0;        \
  uint4 X1 = R1;        \
  uint4 X2 = R2;        \
  uint4 X3 = R3;        \
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

DECLSPEC void salsa_r (uint4 *TI)
{
  uint4 R0 = TI[STATE_CNT4 - 4];
  uint4 R1 = TI[STATE_CNT4 - 3];
  uint4 R2 = TI[STATE_CNT4 - 2];
  uint4 R3 = TI[STATE_CNT4 - 1];

  uint4 TO[STATE_CNT4];

  int idx_y  = 0;
  int idx_r1 = 0;
  int idx_r2 = SCRYPT_R * 4;

  for (int i = 0; i < SCRYPT_R; i++)
  {
    uint4 Y0;
    uint4 Y1;
    uint4 Y2;
    uint4 Y3;

    Y0 = TI[idx_y++];
    Y1 = TI[idx_y++];
    Y2 = TI[idx_y++];
    Y3 = TI[idx_y++];

    SALSA20_8_XOR ();

    TO[idx_r1++] = R0;
    TO[idx_r1++] = R1;
    TO[idx_r1++] = R2;
    TO[idx_r1++] = R3;

    Y0 = TI[idx_y++];
    Y1 = TI[idx_y++];
    Y2 = TI[idx_y++];
    Y3 = TI[idx_y++];

    SALSA20_8_XOR ();

    TO[idx_r2++] = R0;
    TO[idx_r2++] = R1;
    TO[idx_r2++] = R2;
    TO[idx_r2++] = R3;
  }

  #pragma unroll
  for (int i = 0; i < STATE_CNT4; i++)
  {
    TI[i] = TO[i];
  }
}

DECLSPEC void scrypt_smix (uint4 *X, uint4 *T, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3)
{
  #define Coord(xd4,y,z) (((xd4) * ySIZE * zSIZE) + ((y) * zSIZE) + (z))
  #define CO Coord(xd4,y,z)

  const u32 ySIZE = SCRYPT_N / SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = get_global_id (0);

  const u32 xd4 = x / 4;
  const u32 xm4 = x & 3;

  GLOBAL_AS uint4 *V;

  switch (xm4)
  {
    case 0: V = V0; break;
    case 1: V = V1; break;
    case 2: V = V2; break;
    case 3: V = V3; break;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    #ifdef IS_CUDA
    T[0] = make_uint4 (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = make_uint4 (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = make_uint4 (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = make_uint4 (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);
    #else
    T[0] = (uint4) (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = (uint4) (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = (uint4) (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = (uint4) (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);
    #endif

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }

  for (u32 y = 0; y < ySIZE; y++)
  {
    for (u32 z = 0; z < zSIZE; z++) V[CO] = X[z];

    for (u32 i = 0; i < SCRYPT_TMTO; i++) salsa_r (X);
  }

  for (u32 i = 0; i < SCRYPT_N; i++)
  {
    const u32 k = X[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k / SCRYPT_TMTO;

    const u32 km = k - (y * SCRYPT_TMTO);

    for (u32 z = 0; z < zSIZE; z++) T[z] = V[CO];

    for (u32 i = 0; i < km; i++) salsa_r (T);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r (X);
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    #ifdef IS_CUDA
    T[0] = make_uint4 (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = make_uint4 (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = make_uint4 (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = make_uint4 (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);
    #else
    T[0] = (uint4) (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = (uint4) (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = (uint4) (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = (uint4) (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);
    #endif

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }
}

KERNEL_FQ void m22700_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // convert password to utf16be:

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_len_utf16be = pw_len * 2;

  u32 w[128] = { 0 };

  for (u32 i = 0, j = 0; i < 64; i += 4, j += 8)
  {
    u32 in[4];

    in[0] = pws[gid].i[i + 0];
    in[1] = pws[gid].i[i + 1];
    in[2] = pws[gid].i[i + 2];
    in[3] = pws[gid].i[i + 3];

    u32 out0[4];
    u32 out1[4];

    make_utf16be_S (in, out0, out1);

    w[j + 0] = out0[0];
    w[j + 1] = out0[1];
    w[j + 2] = out0[2];
    w[j + 3] = out0[3];
    w[j + 4] = out1[0];
    w[j + 5] = out1[1];
    w[j + 6] = out1[2];
    w[j + 7] = out1[3];
  }

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, w, pw_len_utf16be);

  u32 s0[4] = { 0 };
  u32 s1[4] = { 0 };
  u32 s2[4] = { 0 };
  u32 s3[4] = { 0 };

  s0[0] = MULTIBIT_S0;
  s0[1] = MULTIBIT_S1;

  sha256_hmac_update_64 (&sha256_hmac_ctx, s0, s1, s2, s3, 8);

  for (u32 i = 0, j = 1, k = 0; i < SCRYPT_CNT; i += 8, j += 1, k += 2)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
    w0[1] = 0;
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
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    u32 digest[8];

    digest[0] = sha256_hmac_ctx2.opad.h[0];
    digest[1] = sha256_hmac_ctx2.opad.h[1];
    digest[2] = sha256_hmac_ctx2.opad.h[2];
    digest[3] = sha256_hmac_ctx2.opad.h[3];
    digest[4] = sha256_hmac_ctx2.opad.h[4];
    digest[5] = sha256_hmac_ctx2.opad.h[5];
    digest[6] = sha256_hmac_ctx2.opad.h[6];
    digest[7] = sha256_hmac_ctx2.opad.h[7];

    #ifdef IS_CUDA
    const uint4 tmp0 = make_uint4 (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = make_uint4 (digest[4], digest[5], digest[6], digest[7]);
    #else
    const uint4 tmp0 = (uint4) (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = (uint4) (digest[4], digest[5], digest[6], digest[7]);
    #endif

    tmps[gid].P[k + 0] = tmp0;
    tmps[gid].P[k + 1] = tmp1;
  }
}

KERNEL_FQ void m22700_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  GLOBAL_AS uint4 *d_scrypt0_buf = (GLOBAL_AS uint4 *) d_extra0_buf;
  GLOBAL_AS uint4 *d_scrypt1_buf = (GLOBAL_AS uint4 *) d_extra1_buf;
  GLOBAL_AS uint4 *d_scrypt2_buf = (GLOBAL_AS uint4 *) d_extra2_buf;
  GLOBAL_AS uint4 *d_scrypt3_buf = (GLOBAL_AS uint4 *) d_extra3_buf;

  uint4 X[STATE_CNT4];
  uint4 T[STATE_CNT4];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int z = 0; z < STATE_CNT4; z++) X[z] = hc_swap32_4 (tmps[gid].P[z]);

  scrypt_smix (X, T, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[z] = hc_swap32_4 (X[z]);

  #if SCRYPT_P >= 1
  for (int i = STATE_CNT4; i < SCRYPT_CNT4; i += STATE_CNT4)
  {
    for (int z = 0; z < STATE_CNT4; z++) X[z] = hc_swap32_4 (tmps[gid].P[i + z]);

    scrypt_smix (X, T, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf);

    for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[i + z] = hc_swap32_4 (X[z]);
  }
  #endif
}

KERNEL_FQ void m22700_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /**
   * 2nd pbkdf2, creates B
   */

  // convert password to utf16be:

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_len_utf16be = pw_len * 2;

  u32 w[128] = { 0 };

  for (u32 i = 0, j = 0; i < 64; i += 4, j += 8)
  {
    u32 in[4];

    in[0] = pws[gid].i[i + 0];
    in[1] = pws[gid].i[i + 1];
    in[2] = pws[gid].i[i + 2];
    in[3] = pws[gid].i[i + 3];

    u32 out0[4];
    u32 out1[4];

    make_utf16be_S (in, out0, out1);

    w[j + 0] = out0[0];
    w[j + 1] = out0[1];
    w[j + 2] = out0[2];
    w[j + 3] = out0[3];
    w[j + 4] = out1[0];
    w[j + 5] = out1[1];
    w[j + 6] = out1[2];
    w[j + 7] = out1[3];
  }

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_swap (&ctx, w, pw_len_utf16be);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  for (u32 l = 0; l < SCRYPT_CNT4; l += 4)
  {
    uint4 tmp;

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

    sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 1;
  w0[1] = 0;
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
  w3[3] = 0;

  sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&ctx);

  // AES256-CBC decrypt with IV from salt buffer (dynamic, alternative 1):

  u32 key[8];

  key[0] = ctx.opad.h[0];
  key[1] = ctx.opad.h[1];
  key[2] = ctx.opad.h[2];
  key[3] = ctx.opad.h[3];
  key[4] = ctx.opad.h[4];
  key[5] = ctx.opad.h[5];
  key[6] = ctx.opad.h[6];
  key[7] = ctx.opad.h[7];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4];

  iv[0] = salt_bufs[salt_pos].salt_buf[0];
  iv[1] = salt_bufs[salt_pos].salt_buf[1];
  iv[2] = salt_bufs[salt_pos].salt_buf[2];
  iv[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 enc[4];

  enc[0] = salt_bufs[salt_pos].salt_buf[4];
  enc[1] = salt_bufs[salt_pos].salt_buf[5];
  enc[2] = salt_bufs[salt_pos].salt_buf[6];
  enc[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 dec[4];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= iv[0];
  dec[1] ^= iv[1];
  dec[2] ^= iv[2];
  dec[3] ^= iv[3];

  if (is_valid_bitcoinj (dec) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0, 0, 0);
    }

    return;
  }

  // alternative 2 (second block, fixed IV):

  enc[0] = salt_bufs[salt_pos].salt_buf[ 8];
  enc[1] = salt_bufs[salt_pos].salt_buf[ 9];
  enc[2] = salt_bufs[salt_pos].salt_buf[10];
  enc[3] = salt_bufs[salt_pos].salt_buf[11];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= MULTIBIT_IV0;
  dec[1] ^= MULTIBIT_IV1;
  dec[2] ^= MULTIBIT_IV2;
  dec[3] ^= MULTIBIT_IV3;

  if (is_valid_bitcoinj (dec) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0, 0, 0);
    }

    return;
  }
}
