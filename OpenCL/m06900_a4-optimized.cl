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
#include M2S(INCLUDE_PATH/inc_hash_gost94.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL           \
  LOCAL_VK u32 s_tables[4][256];        \
  for (u32 i = lid; i < 256; i += lsz)  \
  {                                     \
    s_tables[0][i] = c_tables[0][i];    \
    s_tables[1][i] = c_tables[1][i];    \
    s_tables[2][i] = c_tables[2][i];    \
    s_tables[3][i] = c_tables[3][i];    \
  }                                     \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_tables = s_tables;
#endif

typedef struct pcfg_hash_ctx
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_tables)[256];
  #endif

  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_gost94 (PRIVATE_AS const u32 *data_in, const u32 len, PRIVATE_AS u32 *dgst, MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_tables)[256] = hc->s_tables;
  #else
  CONSTANT_AS u32a (*s_tables)[256] = c_tables;
  #endif

  u32 data[8];

  for (u32 i = 0; i < 8; i++) data[i] = data_in[i];

  u32 state[16];

  for (u32 i = 0; i < 8; i++) state[i] = 0;

  for (u32 i = 0; i < 8; i++) state[8 + i] = data[i];

  u32 state_m[8];
  u32 data_m[8];
  u32 tmp[8];

  /* gost1 */

  for (u32 i = 0; i < 8; i++) state_m[i] = state[i];
  for (u32 i = 0; i < 8; i++) data_m[i]  = data[i];

  PASS0 (state, tmp, state_m, data_m, s_tables);
  PASS2 (state, tmp, state_m, data_m, s_tables);
  PASS4 (state, tmp, state_m, data_m, s_tables);
  PASS6 (state, tmp, state_m, data_m, s_tables);

  SHIFT12 (state_m, data, tmp);
  SHIFT16 (state, data_m, state_m);
  SHIFT61 (state, data_m);

  /* gost2, the length in bits */

  data[0] = len * 8;

  for (u32 i = 1; i < 8; i++) data[i] = 0;

  for (u32 i = 0; i < 8; i++) state_m[i] = state[i];
  for (u32 i = 0; i < 8; i++) data_m[i]  = data[i];

  PASS0 (state, tmp, state_m, data_m, s_tables);
  PASS2 (state, tmp, state_m, data_m, s_tables);
  PASS4 (state, tmp, state_m, data_m, s_tables);
  PASS6 (state, tmp, state_m, data_m, s_tables);

  SHIFT12 (state_m, data, tmp);
  SHIFT16 (state, data_m, state_m);
  SHIFT61 (state, data_m);

  /* gost3, the checksum */

  for (u32 i = 0; i < 8; i++) data[i] = state[8 + i];

  for (u32 i = 0; i < 8; i++) state_m[i] = state[i];
  for (u32 i = 0; i < 8; i++) data_m[i]  = data[i];

  PASS0 (state, tmp, state_m, data_m, s_tables);
  PASS2 (state, tmp, state_m, data_m, s_tables);
  PASS4 (state, tmp, state_m, data_m, s_tables);
  PASS6 (state, tmp, state_m, data_m, s_tables);

  SHIFT12 (state_m, data, tmp);
  SHIFT16 (state, data_m, state_m);
  SHIFT61 (state, data_m);

  dgst[0] = state[0];
  dgst[1] = state[1];
  dgst[2] = state[2];
  dgst[3] = state[3];

  return true;
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  return pcfg_gost94 (w, len, dgst, hc);
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_gost94 (t, len, dgst, hc);
}

#define PCFG_KERNEL_MXX m06900_mxx
#define PCFG_KERNEL_SXX m06900_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
