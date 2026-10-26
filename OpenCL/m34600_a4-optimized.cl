/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md6.cl)
#endif

typedef struct pcfg_hash_ctx
{
  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_md6_256 (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  // the zero init is the padding: everything the key/control words and B do not cover stays zero

  u64 A[2048] = { 0 }; // min 1753 for MD6-256
  u64 N[29]   = { 0 };
  u64 B[4]    = { 0 };

  // PT_GENERATE_LE hands the candidate over little endian, MD6 reads its data words big endian

  B[0] = hc_swap64_S (hl32_to_64_S (w[1], w[0]));
  B[1] = hc_swap64_S (hl32_to_64_S (w[3], w[2]));
  B[2] = hc_swap64_S (hl32_to_64_S (w[5], w[4]));
  B[3] = hc_swap64_S (hl32_to_64_S (w[7], w[6]));

  const u64 databitlen = (u64) len * 8;
  const u64 p = (u64) (md6_b * md6_w) - databitlen;
  const u64 V = (MD6_Vs | (p << 20) | MD6_Ve); // only p change, so we can use precomputed values

  N[ 0] = MD6_Q[ 0];
  N[ 1] = MD6_Q[ 1];
  N[ 2] = MD6_Q[ 2];
  N[ 3] = MD6_Q[ 3];
  N[ 4] = MD6_Q[ 4];
  N[ 5] = MD6_Q[ 5];
  N[ 6] = MD6_Q[ 6];
  N[ 7] = MD6_Q[ 7];
  N[ 8] = MD6_Q[ 8];
  N[ 9] = MD6_Q[ 9];
  N[10] = MD6_Q[10];
  N[11] = MD6_Q[11];
  N[12] = MD6_Q[12];
  N[13] = MD6_Q[13];
  N[14] = MD6_Q[14];
  N[15] = 0;
  N[16] = 0;
  N[17] = 0;
  N[18] = 0;
  N[19] = 0;
  N[20] = 0;
  N[21] = 0;
  N[22] = 0;
  N[23] = MD6_256_DEFAULT_NODEID;
  N[24] = V;
  N[25] = B[0];
  N[26] = B[1];
  N[27] = B[2];
  N[28] = B[3];

  u64 x;

  u64 S = MD6_S0;

  u32 i = 0;
  u32 j = 0;

  u32 rXc = MD6_256_ROUNDS * md6_c;

  for (j = 0; j < 29; j++) A[j] = N[j];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (j = 0, i = md6_n; j < rXc; j += md6_c)
  {
    /*
    ** Unroll loop c=16 times. (One "round" of computation.)
    ** Shift amounts are embedded in macros RLnn.
    */

    RL00
    RL01
    RL02
    RL03
    RL04
    RL05
    RL06
    RL07
    RL08
    RL09
    RL10
    RL11
    RL12
    RL13
    RL14
    RL15

    /* Advance round constant S to the next round constant. */

    S = (S << 1) ^ (S >> (md6_w - 1)) ^ (S & MD6_Smask);

    i += 16;
  }

  u32 off = (MD6_256_ROUNDS - 1) * md6_c + md6_n;

  dgst[0] = l32_from_64_S (A[off+15]);
  dgst[1] = h32_from_64_S (A[off+15]);
  dgst[2] = l32_from_64_S (A[off+14]);
  dgst[3] = h32_from_64_S (A[off+14]);

  return true;
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  return pcfg_md6_256 (w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_md6_256 (t, len, dgst);
}

#define PCFG_KERNEL_MXX m34600_mxx
#define PCFG_KERNEL_SXX m34600_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
