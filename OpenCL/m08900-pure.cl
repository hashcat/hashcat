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

#define Coord(xd4,y,z) (((xd4) * ySIZE * zSIZE) + ((y) * zSIZE) + (z))
#define CO Coord(xd4,y,z)

DECLSPEC void salsa_r (PRIVATE_AS u32 *TI)
{
  u32 x[16];

  for (int j = 0; j < 16; j++) x[j] = TI[STATE_CNT - 16 + j];

  for (int i = 0; i < STATE_CNT; i += 16)
  {
    for (int j = 0; j < 16; j++)
    {
      x[j] ^= TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }

    for (int r = 0; r < 4; r++)
    {
      u32 t0, t1, t2, t3;

      t0 = x[ 0] + x[12];
      t1 = x[ 1] + x[13];
      t2 = x[ 2] + x[14];
      t3 = x[ 3] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 7);
      x[ 5] ^= hc_rotl32_S (t1, 7);
      x[ 6] ^= hc_rotl32_S (t2, 7);
      x[ 7] ^= hc_rotl32_S (t3, 7);

      t0 = x[ 4] + x[ 0];
      t1 = x[ 5] + x[ 1];
      t2 = x[ 6] + x[ 2];
      t3 = x[ 7] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[ 4];
      t1 = x[ 9] + x[ 5];
      t2 = x[10] + x[ 6];
      t3 = x[11] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 13);
      x[13] ^= hc_rotl32_S (t1, 13);
      x[14] ^= hc_rotl32_S (t2, 13);
      x[15] ^= hc_rotl32_S (t3, 13);

      t0 = x[12] + x[ 8];
      t1 = x[13] + x[ 9];
      t2 = x[14] + x[10];
      t3 = x[15] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 7]; x[ 7] = x[ 6]; x[ 6] = x[ 5]; x[ 5] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[12]; x[12] = x[13]; x[13] = x[14]; x[14] = x[15]; x[15] = t0;

      t0 = x[ 0] + x[ 4];
      t1 = x[ 1] + x[ 5];
      t2 = x[ 2] + x[ 6];
      t3 = x[ 3] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 7);
      x[13] ^= hc_rotl32_S (t1, 7);
      x[14] ^= hc_rotl32_S (t2, 7);
      x[15] ^= hc_rotl32_S (t3, 7);

      t0 = x[12] + x[ 0];
      t1 = x[13] + x[ 1];
      t2 = x[14] + x[ 2];
      t3 = x[15] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[12];
      t1 = x[ 9] + x[13];
      t2 = x[10] + x[14];
      t3 = x[11] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 13);
      x[ 5] ^= hc_rotl32_S (t1, 13);
      x[ 6] ^= hc_rotl32_S (t2, 13);
      x[ 7] ^= hc_rotl32_S (t3, 13);

      t0 = x[ 4] + x[ 8];
      t1 = x[ 5] + x[ 9];
      t2 = x[ 6] + x[10];
      t3 = x[ 7] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 5]; x[ 5] = x[ 6]; x[ 6] = x[ 7]; x[ 7] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[15]; x[15] = x[14]; x[14] = x[13]; x[13] = x[12]; x[12] = t0;
    }

    for (int j = 0; j < 16; j++)
    {
      x[j] += TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }
  }

  #if SCRYPT_R > 1

  u32 TT[STATE_CNT / 2];

  for (int dst_off = 0, src_off = 16; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TT[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = 16, src_off = 32; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = STATE_CNT / 2, src_off = 0; dst_off < STATE_CNT; dst_off += 16, src_off += 16)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TT[src_off + j];
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

    for (u32 i = 0; i < SCRYPT_TMTO; i++) salsa_r ((u32 *) X);
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

    for (u32 i = 0; i < km; i++) salsa_r ((u32 *) T);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r ((u32 *) X);
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
    #elif defined IS_METAL
    const uint4 tmp0 = uint4 (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = uint4 (digest[4], digest[5], digest[6], digest[7]);
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
    #elif defined IS_METAL
    X[0] = uint4 (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = uint4 (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = uint4 (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = uint4 (T[3].x, T[0].y, T[1].z, T[2].w);
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
    #elif defined IS_METAL
    T[0] = uint4 (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = uint4 (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = uint4 (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = uint4 (X[3].x, X[2].y, X[1].z, X[0].w);
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
