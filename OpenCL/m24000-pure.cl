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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#include M2S(INCLUDE_PATH/inc_cipher_camellia.cl)
#endif

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  uint4 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

typedef struct bestcrypt_scrypt
{
  u32 salt_buf[24];
  u32 ciphertext[96];
  u32 version;

} bestcrypt_scrypt_t;

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

DECLSPEC void scrypt_smix (PRIVATE_AS uint4 *X, PRIVATE_AS uint4 *T, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
{
  #define Coord(xd4,y,z) (((xd4) * ySIZE * zSIZE) + ((y) * zSIZE) + (z))
  #define CO Coord(xd4,y,z)

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

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    #if defined IS_CUDA || defined IS_HIP
    T[0] = make_uint4 (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = make_uint4 (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = make_uint4 (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = make_uint4 (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);
    #elif defined IS_METAL
    T[0] = uint4 (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = uint4 (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = uint4 (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = uint4 (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);
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

    for (u32 i = 0; i < SCRYPT_TMTO; i++) salsa_r ((PRIVATE_AS u32 *) X);
  }

  for (u32 i = 0; i < SCRYPT_N; i++)
  {
    const u32 k = X[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k / SCRYPT_TMTO;

    const u32 km = k - (y * SCRYPT_TMTO);

    for (u32 z = 0; z < zSIZE; z++) T[z] = V[CO];

    for (u32 i = 0; i < km; i++) salsa_r ((PRIVATE_AS u32 *) T);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r ((PRIVATE_AS u32 *) X);
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    #if defined IS_CUDA || defined IS_HIP
    T[0] = make_uint4 (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = make_uint4 (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = make_uint4 (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = make_uint4 (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);
    #elif defined IS_METAL
    T[0] = uint4 (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = uint4 (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = uint4 (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = uint4 (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);
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

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#define Theta1(s) (st[0 + s] ^ st[5 + s] ^ st[10 + s] ^ st[15 + s] ^ st[20 + s])

#define Theta2(s)               \
{                               \
  st[ 0 + s] ^= t;              \
  st[ 5 + s] ^= t;              \
  st[10 + s] ^= t;              \
  st[15 + s] ^= t;              \
  st[20 + s] ^= t;              \
}

#define Rho_Pi(s)               \
{                               \
  u32 j = keccakf_piln[s];      \
  u32 k = keccakf_rotc[s];      \
  bc0 = st[j];                  \
  st[j] = hc_rotl64_S (t, k);   \
  t = bc0;                      \
}

#define Chi(s)                  \
{                               \
  bc0 = st[0 + s];              \
  bc1 = st[1 + s];              \
  bc2 = st[2 + s];              \
  bc3 = st[3 + s];              \
  bc4 = st[4 + s];              \
  st[0 + s] ^= ~bc1 & bc2;      \
  st[1 + s] ^= ~bc2 & bc3;      \
  st[2 + s] ^= ~bc3 & bc4;      \
  st[3 + s] ^= ~bc4 & bc0;      \
  st[4 + s] ^= ~bc0 & bc1;      \
}

CONSTANT_VK u64a keccakf_rndc[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

DECLSPEC void keccak_transform_S (PRIVATE_AS u64 *st)
{
  const u8 keccakf_rotc[24] =
  {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
  };

  const u8 keccakf_piln[24] =
  {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
  };

  /**
   * Keccak
   */

  int round;

  for (round = 0; round < KECCAK_ROUNDS; round++)
  {
    // Theta

    u64 bc0 = Theta1 (0);
    u64 bc1 = Theta1 (1);
    u64 bc2 = Theta1 (2);
    u64 bc3 = Theta1 (3);
    u64 bc4 = Theta1 (4);

    u64 t;

    t = bc4 ^ hc_rotl64_S (bc1, 1); Theta2 (0);
    t = bc0 ^ hc_rotl64_S (bc2, 1); Theta2 (1);
    t = bc1 ^ hc_rotl64_S (bc3, 1); Theta2 (2);
    t = bc2 ^ hc_rotl64_S (bc4, 1); Theta2 (3);
    t = bc3 ^ hc_rotl64_S (bc0, 1); Theta2 (4);

    // Rho Pi

    t = st[1];

    Rho_Pi (0);
    Rho_Pi (1);
    Rho_Pi (2);
    Rho_Pi (3);
    Rho_Pi (4);
    Rho_Pi (5);
    Rho_Pi (6);
    Rho_Pi (7);
    Rho_Pi (8);
    Rho_Pi (9);
    Rho_Pi (10);
    Rho_Pi (11);
    Rho_Pi (12);
    Rho_Pi (13);
    Rho_Pi (14);
    Rho_Pi (15);
    Rho_Pi (16);
    Rho_Pi (17);
    Rho_Pi (18);
    Rho_Pi (19);
    Rho_Pi (20);
    Rho_Pi (21);
    Rho_Pi (22);
    Rho_Pi (23);

    //  Chi

    Chi (0);
    Chi (5);
    Chi (10);
    Chi (15);
    Chi (20);

    //  Iota

    st[0] ^= keccakf_rndc[round];
  }
}

KERNEL_FQ void m24000_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
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
}

KERNEL_FQ void m24000_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  scrypt_smix (X, T, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[z] = hc_swap32_4 (X[z]);

  #if SCRYPT_P >= 1
  for (int i = STATE_CNT4; i < SCRYPT_CNT4; i += STATE_CNT4)
  {
    for (int z = 0; z < STATE_CNT4; z++) X[z] = hc_swap32_4 (tmps[gid].P[i + z]);

    scrypt_smix (X, T, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

    for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[i + z] = hc_swap32_4 (X[z]);
  }
  #endif
}

KERNEL_FQ void m24000_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
{
  /**
   * base
   */

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

  /**
   * AES part
   */

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

  u32 version = esalt_bufs[DIGESTS_OFFSET_HOST].version;

  u32 iv[4] = { 0 };

  u32 res[20]; // full would be 24 x u32 (96 bytes)

  if (version == 0x38) //0x38 is char for '8' which is the crypto type passed in position 3 of hash ( $08$ )
  {

    #define KEYLEN 60

    u32 ks[KEYLEN];

    AES256_set_decrypt_key (ks, ctx.opad.h, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];

      u32 out[4];

      aes256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }


  if (version == 0x39) //0x39 is char for '9' which is the crypto type passed in position 3 of hash ( $09$ )
  {
    u32 sk[4];
    u32 lk[40];

    ctx.opad.h[0] = hc_swap32_S (ctx.opad.h[0]);
    ctx.opad.h[1] = hc_swap32_S (ctx.opad.h[1]);
    ctx.opad.h[2] = hc_swap32_S (ctx.opad.h[2]);
    ctx.opad.h[3] = hc_swap32_S (ctx.opad.h[3]);
    ctx.opad.h[4] = hc_swap32_S (ctx.opad.h[4]);
    ctx.opad.h[5] = hc_swap32_S (ctx.opad.h[5]);
    ctx.opad.h[6] = hc_swap32_S (ctx.opad.h[6]);
    ctx.opad.h[7] = hc_swap32_S (ctx.opad.h[7]);

    twofish256_set_key (sk, lk, ctx.opad.h);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];


      u32 out[4];

      twofish256_decrypt (sk, lk, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  if (version == 0x61) //0x61 is char for 'a' which is the crypto type passed in position 3 of hash ( $0a$ )
  {
    u32 ks_serpent[140];

    ctx.opad.h[0] = hc_swap32_S (ctx.opad.h[0]);
    ctx.opad.h[1] = hc_swap32_S (ctx.opad.h[1]);
    ctx.opad.h[2] = hc_swap32_S (ctx.opad.h[2]);
    ctx.opad.h[3] = hc_swap32_S (ctx.opad.h[3]);
    ctx.opad.h[4] = hc_swap32_S (ctx.opad.h[4]);
    ctx.opad.h[5] = hc_swap32_S (ctx.opad.h[5]);
    ctx.opad.h[6] = hc_swap32_S (ctx.opad.h[6]);
    ctx.opad.h[7] = hc_swap32_S (ctx.opad.h[7]);

    serpent256_set_key (ks_serpent, ctx.opad.h);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];


      u32 out[4];

      serpent256_decrypt (ks_serpent, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  if (version == 0x66) //0x66 is char for 'f' which is the crypto type passed in position 3 of hash ( $0f$ )
  {
    u32 ks_camellia[68];

    ctx.opad.h[0] = hc_swap32_S (ctx.opad.h[0]);
    ctx.opad.h[1] = hc_swap32_S (ctx.opad.h[1]);
    ctx.opad.h[2] = hc_swap32_S (ctx.opad.h[2]);
    ctx.opad.h[3] = hc_swap32_S (ctx.opad.h[3]);
    ctx.opad.h[4] = hc_swap32_S (ctx.opad.h[4]);
    ctx.opad.h[5] = hc_swap32_S (ctx.opad.h[5]);
    ctx.opad.h[6] = hc_swap32_S (ctx.opad.h[6]);
    ctx.opad.h[7] = hc_swap32_S (ctx.opad.h[7]);

    camellia256_set_key (ks_camellia, ctx.opad.h);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];


      u32 out[4];

      camellia256_decrypt (ks_camellia, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  w0[0] = res[ 0];
  w0[1] = res[ 1];
  w0[2] = res[ 2];
  w0[3] = res[ 3];
  w1[0] = res[ 4];
  w1[1] = res[ 5];
  w1[2] = res[ 6];
  w1[3] = res[ 7];
  w2[0] = res[ 8];
  w2[1] = res[ 9];
  w2[2] = res[10];
  w2[3] = res[11];
  w3[0] = res[12];
  w3[1] = res[13];
  w3[2] = res[14];
  w3[3] = res[15];

  sha256_transform (w0, w1, w2, w3, digest);

  w0[0] = 0x80000000;
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
  w3[3] = 64 * 8;

  sha256_transform (w0, w1, w2, w3, digest);

  if ((digest[0] == res[16]) &&
      (digest[1] == res[17]) &&
      (digest[2] == res[18]) &&
      (digest[3] == res[19]))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
