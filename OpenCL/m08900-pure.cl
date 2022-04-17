/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  uint4 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

#if defined IS_CUDA || defined IS_HIP

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

#if defined IS_CUDA || defined IS_HIP

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
#elif defined IS_METAL
#define SALSA20_2R()                        \
{                                           \
  ADD_ROTATE_XOR (X1, X0, X3,  7);          \
  ADD_ROTATE_XOR (X2, X1, X0,  9);          \
  ADD_ROTATE_XOR (X3, X2, X1, 13);          \
  ADD_ROTATE_XOR (X0, X3, X2, 18);          \
                                            \
  X1 = X1.wxyz;                             \
  X2 = X2.zwxy;                             \
  X3 = X3.yzwx;                             \
                                            \
  ADD_ROTATE_XOR (X3, X0, X1,  7);          \
  ADD_ROTATE_XOR (X2, X3, X0,  9);          \
  ADD_ROTATE_XOR (X1, X2, X3, 13);          \
  ADD_ROTATE_XOR (X0, X1, X2, 18);          \
                                            \
  X1 = X1.yzwx;                             \
  X2 = X2.zwxy;                             \
  X3 = X3.wxyz;                             \
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

#define Coord(xd4,y,z) (((xd4) * ySIZE * zSIZE) + ((y) * zSIZE) + (z))
#define CO Coord(xd4,y,z)

DECLSPEC void salsa_r (PRIVATE_AS uint4 *TI)
{
  uint4 R0 = TI[STATE_CNT4 - 4];
  uint4 R1 = TI[STATE_CNT4 - 3];
  uint4 R2 = TI[STATE_CNT4 - 2];
  uint4 R3 = TI[STATE_CNT4 - 1];

  for (int i = 0; i < STATE_CNT4; i += 4)
  {
    uint4 Y0 = TI[i + 0];
    uint4 Y1 = TI[i + 1];
    uint4 Y2 = TI[i + 2];
    uint4 Y3 = TI[i + 3];

    R0 = R0 ^ Y0;
    R1 = R1 ^ Y1;
    R2 = R2 ^ Y2;
    R3 = R3 ^ Y3;

    uint4 X0 = R0;
    uint4 X1 = R1;
    uint4 X2 = R2;
    uint4 X3 = R3;

    SALSA20_2R ();
    SALSA20_2R ();
    SALSA20_2R ();
    SALSA20_2R ();

    R0 = R0 + X0;
    R1 = R1 + X1;
    R2 = R2 + X2;
    R3 = R3 + X3;

    TI[i + 0] = R0;
    TI[i + 1] = R1;
    TI[i + 2] = R2;
    TI[i + 3] = R3;
  }

  #if SCRYPT_R > 1

  uint4 TT[STATE_CNT4 / 2];

  for (int dst_off = 0, src_off = 4; src_off < STATE_CNT4; dst_off += 4, src_off += 8)
  {
    TT[dst_off + 0] = TI[src_off + 0];
    TT[dst_off + 1] = TI[src_off + 1];
    TT[dst_off + 2] = TI[src_off + 2];
    TT[dst_off + 3] = TI[src_off + 3];
  }

  for (int dst_off = 4, src_off = 8; src_off < STATE_CNT4; dst_off += 4, src_off += 8)
  {
    TI[dst_off + 0] = TI[src_off + 0];
    TI[dst_off + 1] = TI[src_off + 1];
    TI[dst_off + 2] = TI[src_off + 2];
    TI[dst_off + 3] = TI[src_off + 3];
  }

  for (int dst_off = STATE_CNT4 / 2, src_off = 0; dst_off < STATE_CNT4; dst_off += 4, src_off += 4)
  {
    TI[dst_off + 0] = TT[src_off + 0];
    TI[dst_off + 1] = TT[src_off + 1];
    TI[dst_off + 2] = TT[src_off + 2];
    TI[dst_off + 3] = TT[src_off + 3];
  }

  #endif
}

DECLSPEC void scrypt_smix_init (PRIVATE_AS uint4 *X, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
{
  const u32 ySIZE = SCRYPT_N / SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = (u32) gid;

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

  for (u32 y = 0; y < ySIZE; y++)
  {
    for (u32 z = 0; z < zSIZE; z++) V[CO] = X[z];

    for (u32 i = 0; i < SCRYPT_TMTO; i++) salsa_r (X);
  }
}

DECLSPEC void scrypt_smix_loop (PRIVATE_AS uint4 *X, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
{
  const u32 ySIZE = SCRYPT_N / SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = (u32) gid;

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

  // note: fixed 1024 iterations = forced -u 1024

  for (u32 N_pos = 0; N_pos < 1024; N_pos++)
  {
    const u32 k = X[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k / SCRYPT_TMTO;

    const u32 km = k - (y * SCRYPT_TMTO);

    uint4 T[STATE_CNT4];

    for (u32 z = 0; z < zSIZE; z++) T[z] = V[CO];

    for (u32 i = 0; i < km; i++) salsa_r (T);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r (X);
  }
}

KERNEL_FQ void m08900_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

    #if defined IS_CUDA || defined IS_HIP
    const uint4 tmp0 = make_uint4 (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = make_uint4 (digest[4], digest[5], digest[6], digest[7]);
    #else
    const uint4 tmp0 = (uint4) (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = (uint4) (digest[4], digest[5], digest[6], digest[7]);
    #endif

    tmps[gid].P[k + 0] = tmp0;
    tmps[gid].P[k + 1] = tmp1;
  }

  for (u32 l = 0; l < SCRYPT_CNT4; l += 4)
  {
    uint4 T[4];

    T[0] = tmps[gid].P[l + 0];
    T[1] = tmps[gid].P[l + 1];
    T[2] = tmps[gid].P[l + 2];
    T[3] = tmps[gid].P[l + 3];

    T[0] = hc_swap32_4 (T[0]);
    T[1] = hc_swap32_4 (T[1]);
    T[2] = hc_swap32_4 (T[2]);
    T[3] = hc_swap32_4 (T[3]);

    uint4 X[4];

    #if defined IS_CUDA || defined IS_HIP
    X[0] = make_uint4 (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = make_uint4 (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = make_uint4 (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = make_uint4 (T[3].x, T[0].y, T[1].z, T[2].w);
    #else
    X[0] = (uint4) (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = (uint4) (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = (uint4) (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = (uint4) (T[3].x, T[0].y, T[1].z, T[2].w);
    #endif

    tmps[gid].P[l + 0] = X[0];
    tmps[gid].P[l + 1] = X[1];
    tmps[gid].P[l + 2] = X[2];
    tmps[gid].P[l + 3] = X[3];
  }
}

KERNEL_FQ void m08900_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  // SCRYPT part, init V

  GLOBAL_AS uint4 *d_scrypt0_buf = (GLOBAL_AS uint4 *) d_extra0_buf;
  GLOBAL_AS uint4 *d_scrypt1_buf = (GLOBAL_AS uint4 *) d_extra1_buf;
  GLOBAL_AS uint4 *d_scrypt2_buf = (GLOBAL_AS uint4 *) d_extra2_buf;
  GLOBAL_AS uint4 *d_scrypt3_buf = (GLOBAL_AS uint4 *) d_extra3_buf;

  uint4 X[STATE_CNT4];

  const u32 P_offset = SALT_REPEAT * STATE_CNT4;

  GLOBAL_AS uint4 *P = tmps[gid].P + P_offset;

  for (int z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_init (X, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

  for (int z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void m08900_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS uint4 *d_scrypt0_buf = (GLOBAL_AS uint4 *) d_extra0_buf;
  GLOBAL_AS uint4 *d_scrypt1_buf = (GLOBAL_AS uint4 *) d_extra1_buf;
  GLOBAL_AS uint4 *d_scrypt2_buf = (GLOBAL_AS uint4 *) d_extra2_buf;
  GLOBAL_AS uint4 *d_scrypt3_buf = (GLOBAL_AS uint4 *) d_extra3_buf;

  uint4 X[STATE_CNT4];

  const u32 P_offset = SALT_REPEAT * STATE_CNT4;

  GLOBAL_AS uint4 *P = tmps[gid].P + P_offset;

  for (int z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_loop (X, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

  for (int z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void m08900_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  /**
   * 2nd pbkdf2, creates B
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  for (u32 l = 0; l < SCRYPT_CNT4; l += 4)
  {
    uint4 X[4];

    X[0] = tmps[gid].P[l + 0];
    X[1] = tmps[gid].P[l + 1];
    X[2] = tmps[gid].P[l + 2];
    X[3] = tmps[gid].P[l + 3];

    uint4 T[4];

    #if defined IS_CUDA || defined IS_HIP
    T[0] = make_uint4 (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = make_uint4 (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = make_uint4 (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = make_uint4 (X[3].x, X[2].y, X[1].z, X[0].w);
    #else
    T[0] = (uint4) (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = (uint4) (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = (uint4) (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = (uint4) (X[3].x, X[2].y, X[1].z, X[0].w);
    #endif

    T[0] = hc_swap32_4 (T[0]);
    T[1] = hc_swap32_4 (T[1]);
    T[2] = hc_swap32_4 (T[2]);
    T[3] = hc_swap32_4 (T[3]);

    w0[0] = T[0].x;
    w0[1] = T[0].y;
    w0[2] = T[0].z;
    w0[3] = T[0].w;
    w1[0] = T[1].x;
    w1[1] = T[1].y;
    w1[2] = T[1].z;
    w1[3] = T[1].w;
    w2[0] = T[2].x;
    w2[1] = T[2].y;
    w2[2] = T[2].z;
    w2[3] = T[2].w;
    w3[0] = T[3].x;
    w3[1] = T[3].y;
    w3[2] = T[3].z;
    w3[3] = T[3].w;

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

  const u32 r0 = hc_swap32_S (ctx.opad.h[DGST_R0]);
  const u32 r1 = hc_swap32_S (ctx.opad.h[DGST_R1]);
  const u32 r2 = hc_swap32_S (ctx.opad.h[DGST_R2]);
  const u32 r3 = hc_swap32_S (ctx.opad.h[DGST_R3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
