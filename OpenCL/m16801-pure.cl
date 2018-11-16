/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}

__kernel void m16801_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];
  in[ 8] = pws[gid].i[ 8];
  in[ 9] = pws[gid].i[ 9];
  in[10] = pws[gid].i[10];
  in[11] = pws[gid].i[11];
  in[12] = pws[gid].i[12];
  in[13] = pws[gid].i[13];
  in[14] = pws[gid].i[14];
  in[15] = pws[gid].i[15];

  u8 *in_ptr = (u8 *) in;

  u32 out[8];

  u8 *out_ptr = (u8 *) out;

  for (int i = 0, j = 0; i < 32; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].out[0] = swap32_S (out[0]);
  tmps[gid].out[1] = swap32_S (out[1]);
  tmps[gid].out[2] = swap32_S (out[2]);
  tmps[gid].out[3] = swap32_S (out[3]);
  tmps[gid].out[4] = swap32_S (out[4]);
  tmps[gid].out[5] = swap32_S (out[5]);
  tmps[gid].out[6] = swap32_S (out[6]);
  tmps[gid].out[7] = swap32_S (out[7]);
}

__kernel void m16801_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;
}

__kernel void m16801_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t))
{
  // not in use here, special case...
}

__kernel void m16801_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_pmkid_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = tmps[gid].out[0];
  w[ 1] = tmps[gid].out[1];
  w[ 2] = tmps[gid].out[2];
  w[ 3] = tmps[gid].out[3];
  w[ 4] = tmps[gid].out[4];
  w[ 5] = tmps[gid].out[5];
  w[ 6] = tmps[gid].out[6];
  w[ 7] = tmps[gid].out[7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 digest_pos = loop_pos;

  const u32 digest_cur = digests_offset + digest_pos;

  __global const wpa_pmkid_t *wpa_pmkid = &esalt_bufs[digest_cur];

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init (&sha1_hmac_ctx, w, 32);

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, wpa_pmkid->pmkid_data, 20);

  sha1_hmac_final (&sha1_hmac_ctx);

  const u32 r0 = sha1_hmac_ctx.opad.h[0];
  const u32 r1 = sha1_hmac_ctx.opad.h[1];
  const u32 r2 = sha1_hmac_ctx.opad.h[2];
  const u32 r3 = sha1_hmac_ctx.opad.h[3];

  #define il_pos 0

  #include COMPARE_M
}
