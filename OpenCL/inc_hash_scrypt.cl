/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_scrypt.h"

DECLSPEC hc_uint4_t xor_uint4 (const hc_uint4_t a, const hc_uint4_t b)
{
  hc_uint4_t r;

  r.x = a.x ^ b.x;
  r.y = a.y ^ b.y;
  r.z = a.z ^ b.z;
  r.w = a.w ^ b.w;

  return r;
}

// The single-lane kernel keeps X and T in registers only where every access to them has a constant
// index. With the TMTO a run-time value the replay loop is always there and T has to live across it,
// and at r <= 2 AMD's compiler then kept both arrays in scratch memory, which made mode 9300 a third
// slower under OpenCL on an RX 7900 XTX. So where SCRYPT_SINGLE_REGS asks for it the loops over X and
// T are unrolled and V is copied word by word instead of through a hc_uint4_t cast. Above r=2 the
// arrays do not fit in registers either way, and unrolling there only traded the scratch array for
// spilled registers, which ran 15 percent slower.

#if SCRYPT_R > 1
DECLSPEC void scrypt_shuffle (PRIVATE_AS u32 *TI)
{
  u32 TT[STATE_CNT4 / 2];

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int dst_off = 0, src_off = SALSA_CNT4; src_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4 * 2)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TT[dst_off + j] = TI[src_off + j];
  }

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int dst_off = SALSA_CNT4, src_off = SALSA_CNT4 * 2; src_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4 * 2)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TI[src_off + j];
  }

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int dst_off = STATE_CNT4 / 2, src_off = 0; dst_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TT[src_off + j];
  }
}

DECLSPEC void scrypt_shuffle_inv (PRIVATE_AS u32 *TI)
{
  u32 TT[STATE_CNT4];

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int j = 0; j < STATE_CNT4; j++) TT[j] = TI[j];

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int dst_off = SALSA_CNT4 * 2, src_off = SALSA_CNT4; dst_off < STATE_CNT4; dst_off += SALSA_CNT4 * 2, src_off += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TT[src_off + j];
  }

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int dst_off = SALSA_CNT4, src_off = STATE_CNT4 / 2; dst_off < STATE_CNT4; dst_off += SALSA_CNT4 * 2, src_off += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TT[src_off + j];
  }
}
#endif

DECLSPEC void salsa_r (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (int j = 0; j < SALSA_CNT4; j++) TT[j] = TI[STATE_CNT4 - 16 + j];

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (int i = 0; i < STATE_CNT4; i += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TT[j] ^= TI[i + j];

    for (int j = 0; j < SALSA_CNT4; j++) TI[i + j] = TT[j];

    #if defined SCRYPT_SINGLE_REGS
    #pragma unroll 1
    #endif
    for (int r = 0; r < 4; r++)
    {
      u32 t0, t1, t2, t3;

      t0 = TT[ 0] + TT[12];
      t1 = TT[ 1] + TT[13];
      t2 = TT[ 2] + TT[14];
      t3 = TT[ 3] + TT[15];
      TT[ 4] ^= hc_rotl32_S (t0, 7);
      TT[ 5] ^= hc_rotl32_S (t1, 7);
      TT[ 6] ^= hc_rotl32_S (t2, 7);
      TT[ 7] ^= hc_rotl32_S (t3, 7);

      t0 = TT[ 4] + TT[ 0];
      t1 = TT[ 5] + TT[ 1];
      t2 = TT[ 6] + TT[ 2];
      t3 = TT[ 7] + TT[ 3];
      TT[ 8] ^= hc_rotl32_S (t0, 9);
      TT[ 9] ^= hc_rotl32_S (t1, 9);
      TT[10] ^= hc_rotl32_S (t2, 9);
      TT[11] ^= hc_rotl32_S (t3, 9);

      t0 = TT[ 8] + TT[ 4];
      t1 = TT[ 9] + TT[ 5];
      t2 = TT[10] + TT[ 6];
      t3 = TT[11] + TT[ 7];
      TT[12] ^= hc_rotl32_S (t0, 13);
      TT[13] ^= hc_rotl32_S (t1, 13);
      TT[14] ^= hc_rotl32_S (t2, 13);
      TT[15] ^= hc_rotl32_S (t3, 13);

      t0 = TT[12] + TT[ 8];
      t1 = TT[13] + TT[ 9];
      t2 = TT[14] + TT[10];
      t3 = TT[15] + TT[11];
      TT[ 0] ^= hc_rotl32_S (t0, 18);
      TT[ 1] ^= hc_rotl32_S (t1, 18);
      TT[ 2] ^= hc_rotl32_S (t2, 18);
      TT[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = TT[ 4]; TT[ 4] = TT[ 7]; TT[ 7] = TT[ 6]; TT[ 6] = TT[ 5]; TT[ 5] = t0;
      t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
      t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
      t0 = TT[12]; TT[12] = TT[13]; TT[13] = TT[14]; TT[14] = TT[15]; TT[15] = t0;

      t0 = TT[ 0] + TT[ 4];
      t1 = TT[ 1] + TT[ 5];
      t2 = TT[ 2] + TT[ 6];
      t3 = TT[ 3] + TT[ 7];
      TT[12] ^= hc_rotl32_S (t0, 7);
      TT[13] ^= hc_rotl32_S (t1, 7);
      TT[14] ^= hc_rotl32_S (t2, 7);
      TT[15] ^= hc_rotl32_S (t3, 7);

      t0 = TT[12] + TT[ 0];
      t1 = TT[13] + TT[ 1];
      t2 = TT[14] + TT[ 2];
      t3 = TT[15] + TT[ 3];
      TT[ 8] ^= hc_rotl32_S (t0, 9);
      TT[ 9] ^= hc_rotl32_S (t1, 9);
      TT[10] ^= hc_rotl32_S (t2, 9);
      TT[11] ^= hc_rotl32_S (t3, 9);

      t0 = TT[ 8] + TT[12];
      t1 = TT[ 9] + TT[13];
      t2 = TT[10] + TT[14];
      t3 = TT[11] + TT[15];
      TT[ 4] ^= hc_rotl32_S (t0, 13);
      TT[ 5] ^= hc_rotl32_S (t1, 13);
      TT[ 6] ^= hc_rotl32_S (t2, 13);
      TT[ 7] ^= hc_rotl32_S (t3, 13);

      t0 = TT[ 4] + TT[ 8];
      t1 = TT[ 5] + TT[ 9];
      t2 = TT[ 6] + TT[10];
      t3 = TT[ 7] + TT[11];
      TT[ 0] ^= hc_rotl32_S (t0, 18);
      TT[ 1] ^= hc_rotl32_S (t1, 18);
      TT[ 2] ^= hc_rotl32_S (t2, 18);
      TT[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = TT[ 4]; TT[ 4] = TT[ 5]; TT[ 5] = TT[ 6]; TT[ 6] = TT[ 7]; TT[ 7] = t0;
      t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
      t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
      t0 = TT[15]; TT[15] = TT[14]; TT[14] = TT[13]; TT[13] = TT[12]; TT[12] = t0;
    }

    for (int j = 0; j < SALSA_CNT4; j++) TT[j] += TI[i + j];

    for (int j = 0; j < SALSA_CNT4; j++) TI[i + j] = TT[j];
  }
}

#ifdef SCRYPT_N

// The V region of one lane as the single-lane kernels have always laid it out: the four buffers take
// every fourth work group, and the lanes of a work group sit side by side in them.

DECLSPEC GLOBAL_AS hc_uint4_t *scrypt_v_lane (GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u32 lid, const u32 lsz, const u32 bid)
{
  const u32 ySIZE = SCRYPT_N >> SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT44;

  const u32 xd4 = bid / 4;
  const u32 xm4 = bid & 3;

  GLOBAL_AS hc_uint4_t *V = 0;

  switch (xm4)
  {
    case 0: V = (GLOBAL_AS hc_uint4_t *) V0; break;
    case 1: V = (GLOBAL_AS hc_uint4_t *) V1; break;
    case 2: V = (GLOBAL_AS hc_uint4_t *) V2; break;
    case 3: V = (GLOBAL_AS hc_uint4_t *) V3; break;
  }

  GLOBAL_AS hc_uint4_t *Vx = V + (xd4 * lsz * ySIZE * zSIZE) + (lid * ySIZE * zSIZE);

  return Vx;
}

#endif

// The V region of one candidate where kernel_accel counts candidates, which is what
// OPTS_TYPE_THREAD_MULTI_DISABLE makes it: the four buffers take every fourth candidate. The
// four-lane and the single-lane path both use it, so they size the buffers the same way.

DECLSPEC GLOBAL_AS hc_uint4_t *scrypt_v_candidate (GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 c, const u32 n, const u32 tmto)
{
  const u64 ySIZE = n >> tmto;
  const u64 zSIZE = STATE_CNT44;

  GLOBAL_AS hc_uint4_t *V = 0;

  switch (c & 3)
  {
    case 0: V = (GLOBAL_AS hc_uint4_t *) V0; break;
    case 1: V = (GLOBAL_AS hc_uint4_t *) V1; break;
    case 2: V = (GLOBAL_AS hc_uint4_t *) V2; break;
    case 3: V = (GLOBAL_AS hc_uint4_t *) V3; break;
  }

  GLOBAL_AS hc_uint4_t *Vx = V + ((c >> 2) * ySIZE * zSIZE);

  return Vx;
}

DECLSPEC void scrypt_smix_init_v (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, GLOBAL_AS hc_uint4_t *Vx, const u32 n, const u32 tmto)
{
  const u32 ySIZE = n >> tmto;
  const u32 zSIZE = STATE_CNT44;

  #ifndef SCRYPT_SINGLE_REGS
  PRIVATE_AS hc_uint4_t *X4 = (PRIVATE_AS hc_uint4_t *) X;
  #endif

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i++) X[i] = P[i];

  #if SCRYPT_R > 1
  scrypt_shuffle_inv (X);
  #endif

  for (u32 y = 0; y < ySIZE; y++)
  {
    GLOBAL_AS hc_uint4_t *Vxx = Vx + (y * zSIZE);

    #if defined SCRYPT_SINGLE_REGS
    #pragma unroll
    for (u32 z = 0; z < zSIZE; z++)
    {
      hc_uint4_t v;

      v.x = X[(z * 4) + 0];
      v.y = X[(z * 4) + 1];
      v.z = X[(z * 4) + 2];
      v.w = X[(z * 4) + 3];

      Vxx[z] = v;
    }
    #else
    for (u32 z = 0; z < zSIZE; z++) Vxx[z] = X4[z];
    #endif

    for (u32 i = 0; i < (1u << tmto); i++)
    {
      #if SCRYPT_R > 1
      scrypt_shuffle (X);
      #endif

      salsa_r (X);
    }
  }

  #if SCRYPT_R > 1
  scrypt_shuffle (X);
  #endif

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i++) P[i] = X[i];
}

DECLSPEC void scrypt_smix_loop_v (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, PRIVATE_AS u32 *T, GLOBAL_AS hc_uint4_t *Vx, const u32 n, const u32 tmto, const u64 loop_cnt)
{
  const u32 zSIZE = STATE_CNT44;

  #ifndef SCRYPT_SINGLE_REGS
  PRIVATE_AS hc_uint4_t *X4 = (PRIVATE_AS hc_uint4_t *) X;
  PRIVATE_AS hc_uint4_t *T4 = (PRIVATE_AS hc_uint4_t *) T;
  #endif

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i++) X[i] = P[i];

  #if SCRYPT_R > 1
  scrypt_shuffle_inv (X);
  #endif

  const u32 N_max = (loop_cnt < SCRYPT_LOOP_MAX (n)) ? (u32) loop_cnt : SCRYPT_LOOP_MAX (n);

  for (u32 N_pos = 0; N_pos < N_max; N_pos++)
  {
    #if defined SCRYPT_SINGLE_REGS
    const u32 k = X[STATE_CNT4 - 16] & (n - 1);
    #else
    const u32 k = X4[zSIZE - 4].x & (n - 1);
    #endif

    const u32 y = k >> tmto;

    const u32 km = k - (y << tmto);

    GLOBAL_AS hc_uint4_t *Vxx = Vx + (y * zSIZE);

    #if defined SCRYPT_SINGLE_REGS
    #pragma unroll
    for (u32 z = 0; z < zSIZE; z++)
    {
      const hc_uint4_t v = Vxx[z];

      T[(z * 4) + 0] = v.x;
      T[(z * 4) + 1] = v.y;
      T[(z * 4) + 2] = v.z;
      T[(z * 4) + 3] = v.w;
    }
    #else
    for (u32 z = 0; z < zSIZE; z++) T4[z] = *Vxx++;
    #endif

    for (u32 i = 0; i < km; i++)
    {
      #if SCRYPT_R > 1
      scrypt_shuffle (T);
      #endif

      salsa_r (T);
    }

    #if defined SCRYPT_SINGLE_REGS
    #pragma unroll
    for (u32 i = 0; i < STATE_CNT4; i++) X[i] ^= T[i];
    #else
    for (u32 z = 0; z < zSIZE; z++) X4[z] = xor_uint4 (X4[z], T4[z]);
    #endif

    #if SCRYPT_R > 1
    scrypt_shuffle (X);
    #endif

    salsa_r (X);
  }

  #if SCRYPT_R > 1
  scrypt_shuffle (X);
  #endif

  #if defined SCRYPT_SINGLE_REGS
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i++) P[i] = X[i];
}

#ifdef SCRYPT_N

DECLSPEC void scrypt_smix_init (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u32 gid, const u32 lid, const u32 lsz, const u32 bid)
{
  scrypt_smix_init_v (P, X, scrypt_v_lane (V0, V1, V2, V3, lid, lsz, bid), SCRYPT_N, SCRYPT_TMTO);
}

DECLSPEC void scrypt_smix_loop (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, PRIVATE_AS u32 *T, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u32 gid, const u32 lid, const u32 lsz, const u32 bid)
{
  scrypt_smix_loop_v (P, X, T, scrypt_v_lane (V0, V1, V2, V3, lid, lsz, bid), SCRYPT_N, SCRYPT_TMTO, SCRYPT_LOOP_MAX (SCRYPT_N));
}

#endif

#if defined SCRYPT_COOP_LANES

// Four lanes compute one candidate, SCRYPT_COOP_GROUP candidates to a work group.
// scrypt_blockmix_in stores every 64-byte block so that words q, 4+q, 8+q and 12+q form
// quarter-round q, so lane q keeps that column of every block and computes its own quarter-round. The
// columns only meet where the rows rotate between the column and the row round, and that is an
// exchange within the 4 lanes.
//
// Every lane of a work group has to reach every exchange, so nothing branches around one. A lane
// without a candidate computes on zeros and stores nothing.

#define COOP_CNT4 (STATE_CNT4 / 4)

#if defined IS_CUDA && (SCRYPT_R == 16)

// Keep r16 warp exchanges inline when NVRTC outlines its sync builtins.

DECLSPEC HC_INLINE_ALWAYS u32 scrypt_cuda_shfl (const u32 v, const u32 s)
{
  u32 r;

  asm volatile ("shfl.sync.idx.b32 %0, %1, %2, 0x1c1f, %3;" : "=r"(r) : "r"(v), "r"(s), "n"(0xffffffff));

  return r;
}

DECLSPEC HC_INLINE_ALWAYS u32 scrypt_cuda_any (const u32 p)
{
  u32 r;

  asm volatile ("{ .reg .pred t; setp.ne.u32 t, %1, 0; vote.sync.any.pred t, t, %2; selp.u32 %0, 1, 0, t; }" : "=r"(r) : "r"(p), "n"(0xffffffff));

  return r;
}

#define COOP_SHFL(v,s) scrypt_cuda_shfl ((v), (s))
#define COOP_ANY(p)    scrypt_cuda_any (p)

#elif defined IS_CUDA

#define COOP_SHFL(v,s) __shfl_sync (0xffffffff, (v), (s), 4)
#define COOP_ANY(p)    __any_sync (0xffffffff, (p))

#elif defined IS_HIP

#define COOP_SHFL(v,s) __shfl ((v), (s), 4)
#define COOP_ANY(p)    __any (p)

#elif defined IS_NV && defined IS_GPU

// NVIDIA's OpenCL compiler takes PTX, which is what the CUDA builtins above lower to. 0x1c1f is
// the clamp and segment mask of a shuffle 4 lanes wide.

DECLSPEC u32 scrypt_coop_shfl (const u32 v, const u32 s)
{
  u32 r;

  asm volatile ("shfl.sync.idx.b32 %0, %1, %2, 0x1c1f, 0xffffffff;" : "=r"(r) : "r"(v), "r"(s));

  return r;
}

DECLSPEC int scrypt_coop_any (const int p)
{
  int r;

  asm volatile ("{ .reg .pred t; setp.ne.s32 t, %1, 0; vote.sync.any.pred t, t, 0xffffffff; selp.s32 %0, 1, 0, t; }" : "=r"(r) : "r"(p));

  return r;
}

#define COOP_SHFL(v,s) scrypt_coop_shfl ((v), (s))
#define COOP_ANY(p)    scrypt_coop_any (p)

#elif defined HC_SHFL_AMDGCN

// ds_bpermute addresses a lane of the whole wave in bytes. A work group of 32 lanes starts at lane 0
// of its wave, on wave64 as well.

DECLSPEC u32 scrypt_coop_shfl (const u32 v, const u32 s)
{
  const u32 self = __builtin_amdgcn_mbcnt_hi (~0u, __builtin_amdgcn_mbcnt_lo (~0u, 0u));

  const u32 idx = ((self & 0x1c) | s) << 2;

  const u32 r = __builtin_amdgcn_ds_bpermute (idx, v);

  return r;
}

// no vote builtin is assumed, so the 32 lanes OR their flags together

DECLSPEC int scrypt_coop_any (const int p)
{
  const u32 self = __builtin_amdgcn_mbcnt_hi (~0u, __builtin_amdgcn_mbcnt_lo (~0u, 0u));

  u32 f = (p != 0) ? 1 : 0;

  for (u32 k = 1; k < 32; k <<= 1) f |= __builtin_amdgcn_ds_bpermute ((self ^ k) << 2, f);

  const int r = (int) f;

  return r;
}

#define COOP_SHFL(v,s) scrypt_coop_shfl ((v), (s))
#define COOP_ANY(p)    scrypt_coop_any (p)

#endif

// DPP handles fixed quad permutations without using the DS crossbar. Its last argument, bound_ctrl,
// only matters where the source lane is out of range or switched off. A quad permutation never
// leaves the quad and every lane of a quad takes part here, so it changes no value. Setting it lets
// the compiler fold the move into the arithmetic that reads it. A move whose result two
// instructions read keeps it unset, and so does every move at r=8, where folding made mode 15700
// slower on an RX 7900 XTX.

#if defined IS_HIP && defined __HIP_DEVICE_COMPILE__
#if defined __has_builtin
#if __has_builtin (__builtin_amdgcn_mov_dpp)
#define SCRYPT_COOP_DPP
#if SCRYPT_R == 16
#define SCRYPT_COOP_DPP_FUSE true
#else
#define SCRYPT_COOP_DPP_FUSE false
#endif
#endif
#endif
#endif

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_salsa (PRIVATE_AS u32 *S, const u32 q)
{
  u32 a = S[0];
  u32 b = S[1];
  u32 c = S[2];
  u32 d = S[3];

  #if defined SCRYPT_COOP_DPP
  (void) q;
  #else
  const u32 q_p1 = (q + 1) & 3;
  const u32 q_m1 = (q + 3) & 3;
  const u32 q_x2 = (q ^ 2);
  #endif

  // Unrolled, the rounds need no loop counter, no divergence check and no re-read of the lane index
  // between them. At r=8 an RTX 4090 ran 66 percent faster than with the rounds kept in a loop. At
  // r=16, ROCm 7.2.4 did not finish compiling the kernel with the rounds in a loop in 3 hours.

  #pragma unroll
  for (int r = 0; r < 4; r++)
  {
    b ^= hc_rotl32_S (a + d,  7);
    c ^= hc_rotl32_S (b + a,  9);
    d ^= hc_rotl32_S (c + b, 13);
    a ^= hc_rotl32_S (d + c, 18);

    #if defined SCRYPT_COOP_DPP
    b = __builtin_amdgcn_mov_dpp (b, 0x93, 0xf, 0xf, false);
    c = __builtin_amdgcn_mov_dpp (c, 0x4e, 0xf, 0xf, SCRYPT_COOP_DPP_FUSE);
    d = __builtin_amdgcn_mov_dpp (d, 0x39, 0xf, 0xf, SCRYPT_COOP_DPP_FUSE);
    #else
    b = COOP_SHFL (b, q_m1);
    c = COOP_SHFL (c, q_x2);
    d = COOP_SHFL (d, q_p1);
    #endif

    d ^= hc_rotl32_S (a + b,  7);
    c ^= hc_rotl32_S (d + a,  9);
    b ^= hc_rotl32_S (c + d, 13);
    a ^= hc_rotl32_S (b + c, 18);

    #if defined SCRYPT_COOP_DPP
    b = __builtin_amdgcn_mov_dpp (b, 0x39, 0xf, 0xf, SCRYPT_COOP_DPP_FUSE);
    c = __builtin_amdgcn_mov_dpp (c, 0x4e, 0xf, 0xf, SCRYPT_COOP_DPP_FUSE);
    d = __builtin_amdgcn_mov_dpp (d, 0x93, 0xf, 0xf, false);
    #else
    b = COOP_SHFL (b, q_p1);
    c = COOP_SHFL (c, q_x2);
    d = COOP_SHFL (d, q_m1);
    #endif
  }

  S[0] = a;
  S[1] = b;
  S[2] = c;
  S[3] = d;
}

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_blockmix (PRIVATE_AS u32 *S, const u32 q)
{
  u32 T[4];

  for (int w = 0; w < 4; w++) T[w] = S[COOP_CNT4 - 4 + w];

  #pragma unroll
  for (int i = 0; i < COOP_CNT4; i += 4)
  {
    for (int w = 0; w < 4; w++) T[w] ^= S[i + w];

    for (int w = 0; w < 4; w++) S[i + w] = T[w];

    scrypt_coop_salsa (T, q);

    for (int w = 0; w < 4; w++) T[w] += S[i + w];

    for (int w = 0; w < 4; w++) S[i + w] = T[w];
  }
}

// the block order between two BlockMix calls, see scrypt_shuffle (), which a lane does on its own

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_shuffle (PRIVATE_AS u32 *S)
{
  #if SCRYPT_R > 1
  u32 Y[COOP_CNT4];

  #pragma unroll
  for (int k = 0; k < SCRYPT_R; k++)
  {
    for (int w = 0; w < 4; w++)
    {
      Y[((k           ) * 4) + w] = S[((2 * k + 0) * 4) + w];
      Y[((SCRYPT_R + k) * 4) + w] = S[((2 * k + 1) * 4) + w];
    }
  }

  for (int i = 0; i < COOP_CNT4; i++) S[i] = Y[i];
  #endif
}

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_shuffle_inv (PRIVATE_AS u32 *S)
{
  #if SCRYPT_R > 1
  u32 Y[COOP_CNT4];

  #pragma unroll
  for (int k = 0; k < SCRYPT_R; k++)
  {
    for (int w = 0; w < 4; w++)
    {
      Y[((2 * k + 0) * 4) + w] = S[((k           ) * 4) + w];
      Y[((2 * k + 1) * 4) + w] = S[((SCRYPT_R + k) * 4) + w];
    }
  }

  for (int i = 0; i < COOP_CNT4; i++) S[i] = Y[i];
  #endif
}

// A V element keeps the 4 lanes of a block side by side, so a candidate reads 64 contiguous bytes
// per block.

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_v_store (GLOBAL_AS hc_uint4_t *Vy, PRIVATE_AS const u32 *S, const u32 q)
{
  #pragma unroll
  for (int b = 0; b < 2 * SCRYPT_R; b++)
  {
    hc_uint4_t v;

    v.x = S[(b * 4) + 0];
    v.y = S[(b * 4) + 1];
    v.z = S[(b * 4) + 2];
    v.w = S[(b * 4) + 3];

    Vy[(b * 4) + q] = v;
  }
}

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_v_load (GLOBAL_AS const hc_uint4_t *Vy, PRIVATE_AS u32 *S, const u32 q)
{
  #pragma unroll
  for (int b = 0; b < 2 * SCRYPT_R; b++)
  {
    const hc_uint4_t v = Vy[(b * 4) + q];

    S[(b * 4) + 0] = v.x;
    S[(b * 4) + 1] = v.y;
    S[(b * 4) + 2] = v.z;
    S[(b * 4) + 3] = v.w;
  }
}

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_p_load (GLOBAL_AS const u32 *P, PRIVATE_AS u32 *S, const u32 q)
{
  #pragma unroll
  for (int b = 0; b < 2 * SCRYPT_R; b++)
  {
    for (int w = 0; w < 4; w++) S[(b * 4) + w] = P[(b * 16) + (w * 4) + q];
  }
}

DECLSPEC HC_INLINE_ALWAYS void scrypt_coop_p_store (GLOBAL_AS u32 *P, PRIVATE_AS const u32 *S, const u32 q)
{
  #pragma unroll
  for (int b = 0; b < 2 * SCRYPT_R; b++)
  {
    for (int w = 0; w < 4; w++) P[(b * 16) + (w * 4) + q] = S[(b * 4) + w];
  }
}

DECLSPEC void scrypt_coop_smix_init (GLOBAL_AS u32 *P, GLOBAL_AS hc_uint4_t *Vc, const u32 q, const bool active, const u32 n, const u32 tmto)
{
  const u32 ySIZE = n >> tmto;
  const u32 zSIZE = STATE_CNT44;

  u32 X[COOP_CNT4];

  for (int i = 0; i < COOP_CNT4; i++) X[i] = 0;

  if (active == true) scrypt_coop_p_load (P, X, q);

  scrypt_coop_shuffle_inv (X);

  for (u32 y = 0; y < ySIZE; y++)
  {
    if (active == true) scrypt_coop_v_store (Vc + ((u64) y * zSIZE), X, q);

    for (u32 i = 0; i < (1u << tmto); i++)
    {
      scrypt_coop_shuffle (X);

      scrypt_coop_blockmix (X, q);
    }
  }

  scrypt_coop_shuffle (X);

  if (active == true) scrypt_coop_p_store (P, X, q);
}

// At r=16 under HIP, X and T do not both fit in registers, and the loop kernel spilled to scratch
// memory on an RX 7900 XTX. X lives in LDS there instead. Each lane reads and writes only its own
// slots of it, so no barrier is needed.

#if defined IS_HIP && (SCRYPT_R == 16)
#define SCRYPT_COOP_LDS_X
#endif

// The replay count comes from the candidate, so the candidates of a work group would wait for each
// other in every iteration, and an exchange under that divergence takes a slow path. Each pass here
// runs one BlockMix in every lane instead, a replay step on T or the main step on T ^ X, and the work
// group only waits for its last candidate at the end.

DECLSPEC void scrypt_coop_smix_loop (GLOBAL_AS u32 *P, GLOBAL_AS hc_uint4_t *Vc, const u32 q, const bool active, const u32 n, const u32 tmto, const u64 loop_cnt)
{
  #if defined SCRYPT_COOP_LDS_X

  const u32 zSIZE = STATE_CNT44;

  LOCAL_VK u32 LX[COOP_CNT4 * FIXED_LOCAL_SIZE];

  const u32 lx_lane = (u32) get_local_id (0);

  u32 T[COOP_CNT4];

  for (u32 i = 0; i < COOP_CNT4; i++) T[i] = 0;

  if (active == true) scrypt_coop_p_load (P, T, q);

  scrypt_coop_shuffle_inv (T);

  for (u32 i = 0; i < COOP_CNT4; i++) LX[((((i >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4) + (i & 3)] = T[i];

  const u32 N_max = (loop_cnt < SCRYPT_LOOP_MAX (n)) ? (u32) loop_cnt : SCRYPT_LOOP_MAX (n);

  // a lane without a candidate counts as finished from the start

  u32 N_pos = (active == true) ? 0 : N_max;

  // integerify reads word 0 of the last block, which is lane 0's

  const u32 k0 = COOP_SHFL (LX[((((COOP_CNT4 - 4) >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4], 0) & (n - 1);

  const u32 y0 = k0 >> tmto;

  u32 km = k0 - (y0 << tmto);

  if (N_pos < N_max) scrypt_coop_v_load (&Vc[(u64) y0 * zSIZE], T, q);

  while (COOP_ANY (N_pos < N_max))
  {
    const u32 main_mask = ((N_pos < N_max) && (km == 0)) ? 0xffffffff : 0;

    for (u32 i = 0; i < COOP_CNT4; i++) T[i] ^= LX[((((i >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4) + (i & 3)] & main_mask;

    scrypt_coop_shuffle (T);

    scrypt_coop_blockmix (T, q);

    if (main_mask != 0)
    {
      for (u32 i = 0; i < COOP_CNT4; i++) LX[((((i >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4) + (i & 3)] = T[i];

      N_pos++;
    }
    else if (km > 0)
    {
      km--;
    }

    const u32 k = COOP_SHFL (LX[((((COOP_CNT4 - 4) >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4], 0) & (n - 1);

    if ((main_mask != 0) && (N_pos < N_max))
    {
      const u32 y = k >> tmto;

      km = k - (y << tmto);

      scrypt_coop_v_load (&Vc[(u64) y * zSIZE], T, q);
    }
  }

  for (u32 i = 0; i < COOP_CNT4; i++) T[i] = LX[((((i >> 2) * FIXED_LOCAL_SIZE) + lx_lane) * 4) + (i & 3)];

  scrypt_coop_shuffle (T);

  if (active == true) scrypt_coop_p_store (P, T, q);
  #else

  const u32 zSIZE = STATE_CNT44;

  u32 X[COOP_CNT4];
  u32 T[COOP_CNT4];

  for (int i = 0; i < COOP_CNT4; i++) X[i] = 0;
  for (int i = 0; i < COOP_CNT4; i++) T[i] = 0;

  if (active == true) scrypt_coop_p_load (P, X, q);

  scrypt_coop_shuffle_inv (X);

  const u32 N_max = (loop_cnt < SCRYPT_LOOP_MAX (n)) ? (u32) loop_cnt : SCRYPT_LOOP_MAX (n);

  // a lane without a candidate counts as finished from the start

  u32 N_pos = (active == true) ? 0 : N_max;

  // integerify reads word 0 of the last block, which is lane 0's

  const u32 k0 = COOP_SHFL (X[COOP_CNT4 - 4], 0) & (n - 1);

  const u32 y0 = k0 >> tmto;

  u32 km = k0 - (y0 << tmto);

  if (N_pos < N_max) scrypt_coop_v_load (Vc + ((u64) y0 * zSIZE), T, q);

  while (COOP_ANY (N_pos < N_max))
  {
    const u32 main_mask = ((N_pos < N_max) && (km == 0)) ? 0xffffffff : 0;

    for (int i = 0; i < COOP_CNT4; i++) T[i] ^= X[i] & main_mask;

    scrypt_coop_shuffle (T);

    scrypt_coop_blockmix (T, q);

    if (main_mask != 0)
    {
      for (int i = 0; i < COOP_CNT4; i++) X[i] = T[i];

      N_pos++;
    }
    else if (km > 0)
    {
      km--;
    }

    const u32 k = COOP_SHFL (X[COOP_CNT4 - 4], 0) & (n - 1);

    if ((main_mask != 0) && (N_pos < N_max))
    {
      const u32 y = k >> tmto;

      km = k - (y << tmto);

      scrypt_coop_v_load (Vc + ((u64) y * zSIZE), T, q);
    }
  }

  scrypt_coop_shuffle (X);

  if (active == true) scrypt_coop_p_store (P, X, q);
  #endif
}

#endif

// The SMix state of candidate c in a tmps array: out0 is tmps[0].out and stride is sizeof (tmps[0]),
// so the kernel entries below work for every tmps type.

DECLSPEC GLOBAL_AS u32 *scrypt_tmps_out (GLOBAL_AS u32 *out0, const u64 stride, const u64 c, const u32 salt_repeat)
{
  GLOBAL_AS u8 *out0_u8 = (GLOBAL_AS u8 *) out0;

  GLOBAL_AS u32 *out = (GLOBAL_AS u32 *) (out0_u8 + (c * stride));

  GLOBAL_AS u32 *P = out + (salt_repeat * STATE_CNT4);

  return P;
}

// The TMTO module_tune asks for, held to log2 (N) so that V keeps at least one element. The
// self-test runs at its own N in the way the target's N was tuned for, and its N can be the smaller.

DECLSPEC u32 scrypt_tune_tmto_n (const u32 module_tune, const u32 n)
{
  const u32 tmto_tune = SCRYPT_TUNE_TMTO (module_tune);

  u32 tmto = (tmto_tune < 31) ? tmto_tune : 31;

  while ((tmto > 0) && ((n >> tmto) == 0)) tmto--;

  return tmto;
}

// The whole of a loop_prepare and of a loop kernel that runs SMix, for a module that sets
// OPTS_TYPE_THREAD_MULTI_DISABLE. They pick the candidate a lane works for, four lanes to a
// candidate when module_tune asks for the four-lane kernel and one lane to a candidate otherwise, and
// take the TMTO from module_tune as well. The kernels call them through the two macros after them,
// which pass N from the salt, see SCRYPT_SALT_N in inc_hash_scrypt.h.
//
// A loop launch runs loop_cnt iterations of the second loop. The host sets it to the lesser of N and
// the 2048 that every scrypt module fixes kernel_loops at, and autotune times some launches on fewer.
//
// gid, lid and bid are the kernel's get_global_id (0), get_local_id (0) and get_group_id (0). Metal
// only has those inside the kernel function itself.

DECLSPEC void scrypt_smix_init_kernel_n (GLOBAL_AS u32 *out0, const u64 stride, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 gid, const u64 lid, const u64 bid, const u64 gid_cnt, const u32 salt_repeat, const u32 module_tune, const u32 n)
{
  const u32 tmto = scrypt_tune_tmto_n (module_tune, n);

  #if defined SCRYPT_COOP_LANES

  if (SCRYPT_COOP_RUNS (module_tune) == true)
  {
    // a work group past the last candidate leaves whole, inside one every lane stays

    const u64 c0 = bid * SCRYPT_COOP_GROUP;

    if (c0 >= gid_cnt) return;

    const u64 c = c0 + (lid / 4);

    const bool active = (c < gid_cnt);

    GLOBAL_AS u32 *P = scrypt_tmps_out (out0, stride, (active == true) ? c : 0, salt_repeat);

    scrypt_coop_smix_init (P, scrypt_v_candidate (V0, V1, V2, V3, c, n, tmto), lid & 3, active, n, tmto);

    return;
  }

  #endif

  if (gid >= gid_cnt) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = scrypt_tmps_out (out0, stride, gid, salt_repeat);

  scrypt_smix_init_v (P, X, scrypt_v_candidate (V0, V1, V2, V3, gid, n, tmto), n, tmto);
}

DECLSPEC void scrypt_smix_loop_kernel_n (GLOBAL_AS u32 *out0, const u64 stride, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 gid, const u64 lid, const u64 bid, const u64 gid_cnt, const u32 salt_repeat, const u32 module_tune, const u64 loop_cnt, const u32 n)
{
  const u32 tmto = scrypt_tune_tmto_n (module_tune, n);

  #if defined SCRYPT_COOP_LANES

  if (SCRYPT_COOP_RUNS (module_tune) == true)
  {
    const u64 c0 = bid * SCRYPT_COOP_GROUP;

    if (c0 >= gid_cnt) return;

    const u64 c = c0 + (lid / 4);

    const bool active = (c < gid_cnt);

    GLOBAL_AS u32 *P = scrypt_tmps_out (out0, stride, (active == true) ? c : 0, salt_repeat);

    scrypt_coop_smix_loop (P, scrypt_v_candidate (V0, V1, V2, V3, c, n, tmto), lid & 3, active, n, tmto, loop_cnt);

    return;
  }

  #endif

  if (gid >= gid_cnt) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = scrypt_tmps_out (out0, stride, gid, salt_repeat);

  scrypt_smix_loop_v (P, X, T, scrypt_v_candidate (V0, V1, V2, V3, gid, n, tmto), n, tmto, loop_cnt);
}

#define scrypt_smix_init_kernel(out0,stride,V0,V1,V2,V3,gid,lid,bid,gid_cnt,salt_repeat,module_tune)          scrypt_smix_init_kernel_n ((out0), (stride), (V0), (V1), (V2), (V3), (gid), (lid), (bid), (gid_cnt), (salt_repeat), (module_tune), SCRYPT_SALT_N)
#define scrypt_smix_loop_kernel(out0,stride,V0,V1,V2,V3,gid,lid,bid,gid_cnt,salt_repeat,module_tune,loop_cnt) scrypt_smix_loop_kernel_n ((out0), (stride), (V0), (V1), (V2), (V3), (gid), (lid), (bid), (gid_cnt), (salt_repeat), (module_tune), (loop_cnt), SCRYPT_SALT_N)

DECLSPEC void scrypt_blockmix_in (GLOBAL_AS u32 *in_buf, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += SALSA_SZ, j += SALSA_CNT4)
  {
    u32 X[SALSA_CNT4];

    X[ 0] = in_buf[j +  0];
    X[ 1] = in_buf[j +  5];
    X[ 2] = in_buf[j + 10];
    X[ 3] = in_buf[j + 15];
    X[ 4] = in_buf[j +  4];
    X[ 5] = in_buf[j +  9];
    X[ 6] = in_buf[j + 14];
    X[ 7] = in_buf[j +  3];
    X[ 8] = in_buf[j +  8];
    X[ 9] = in_buf[j + 13];
    X[10] = in_buf[j +  2];
    X[11] = in_buf[j +  7];
    X[12] = in_buf[j + 12];
    X[13] = in_buf[j +  1];
    X[14] = in_buf[j +  6];
    X[15] = in_buf[j + 11];

    out_buf[j +  0] = X[ 0];
    out_buf[j +  1] = X[ 1];
    out_buf[j +  2] = X[ 2];
    out_buf[j +  3] = X[ 3];
    out_buf[j +  4] = X[ 4];
    out_buf[j +  5] = X[ 5];
    out_buf[j +  6] = X[ 6];
    out_buf[j +  7] = X[ 7];
    out_buf[j +  8] = X[ 8];
    out_buf[j +  9] = X[ 9];
    out_buf[j + 10] = X[10];
    out_buf[j + 11] = X[11];
    out_buf[j + 12] = X[12];
    out_buf[j + 13] = X[13];
    out_buf[j + 14] = X[14];
    out_buf[j + 15] = X[15];
  }
}

DECLSPEC void scrypt_blockmix_out (GLOBAL_AS u32 *in_buf, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += SALSA_SZ, j += SALSA_CNT4)
  {
    u32 T[SALSA_CNT4];

    T[ 0] = in_buf[j +  0];
    T[ 1] = in_buf[j + 13];
    T[ 2] = in_buf[j + 10];
    T[ 3] = in_buf[j +  7];
    T[ 4] = in_buf[j +  4];
    T[ 5] = in_buf[j +  1];
    T[ 6] = in_buf[j + 14];
    T[ 7] = in_buf[j + 11];
    T[ 8] = in_buf[j +  8];
    T[ 9] = in_buf[j +  5];
    T[10] = in_buf[j +  2];
    T[11] = in_buf[j + 15];
    T[12] = in_buf[j + 12];
    T[13] = in_buf[j +  9];
    T[14] = in_buf[j +  6];
    T[15] = in_buf[j +  3];

    out_buf[j +  0] = T[ 0];
    out_buf[j +  1] = T[ 1];
    out_buf[j +  2] = T[ 2];
    out_buf[j +  3] = T[ 3];
    out_buf[j +  4] = T[ 4];
    out_buf[j +  5] = T[ 5];
    out_buf[j +  6] = T[ 6];
    out_buf[j +  7] = T[ 7];
    out_buf[j +  8] = T[ 8];
    out_buf[j +  9] = T[ 9];
    out_buf[j + 10] = T[10];
    out_buf[j + 11] = T[11];
    out_buf[j + 12] = T[12];
    out_buf[j + 13] = T[13];
    out_buf[j + 14] = T[14];
    out_buf[j + 15] = T[15];
  }
}

DECLSPEC void scrypt_pbkdf2_body_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 1, k = 0; i < out_len; i += 32, j += 1, k += 8)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = *sha256_hmac_ctx;

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

    // this will not work if user specifies output length not a multiple of 4
    // probably never happens...
    // let's hope the compiler will auto optimize this since out_len is very likely
    // a constant at caller level

    if (out_len >= (i +  4)) out_buf[k + 0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    if (out_len >= (i +  8)) out_buf[k + 1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    if (out_len >= (i + 12)) out_buf[k + 2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    if (out_len >= (i + 16)) out_buf[k + 3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    if (out_len >= (i + 20)) out_buf[k + 4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    if (out_len >= (i + 24)) out_buf[k + 5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    if (out_len >= (i + 28)) out_buf[k + 6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    if (out_len >= (i + 32)) out_buf[k + 7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void scrypt_pbkdf2_body_pg (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 1, k = 0; i < out_len; i += 32, j += 1, k += 8)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = *sha256_hmac_ctx;

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

    // this will not work if user specifies output length not a multiple of 4
    // probably never happens...
    // let's hope the compiler will auto optimize this since out_len is very likely
    // a constant at caller level

    if (out_len >= (i +  4)) out_buf[k + 0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    if (out_len >= (i +  8)) out_buf[k + 1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    if (out_len >= (i + 12)) out_buf[k + 2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    if (out_len >= (i + 16)) out_buf[k + 3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    if (out_len >= (i + 20)) out_buf[k + 4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    if (out_len >= (i + 24)) out_buf[k + 5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    if (out_len >= (i + 28)) out_buf[k + 6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    if (out_len >= (i + 32)) out_buf[k + 7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void scrypt_pbkdf2_ppp (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_pgp (PRIVATE_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_gpp (GLOBAL_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ggp (GLOBAL_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ppg (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_pgg (PRIVATE_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_gpg (GLOBAL_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ggg (GLOBAL_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

