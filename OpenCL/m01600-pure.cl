/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_md5.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define PUTCHAR_LE(a,p,c) ((u8 *)(a))[(p)] = (u8) (c)
#define GETCHAR_LE(a,p)   ((u8 *)(a))[(p)]

#define md5apr1_magic0 0x72706124u
#define md5apr1_magic1 0x00002431u

__kernel void m01600_init (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  /**
   * prepare
   */

  md5_ctx_t md5_ctx1;

  md5_init (&md5_ctx1);

  md5_update (&md5_ctx1, w, pw_len);

  md5_update (&md5_ctx1, s, salt_len);

  md5_update (&md5_ctx1, w, pw_len);

  md5_final (&md5_ctx1);

  u32 final[16] = { 0 };

  final[0] = md5_ctx1.h[0];
  final[1] = md5_ctx1.h[1];
  final[2] = md5_ctx1.h[2];
  final[3] = md5_ctx1.h[3];

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, w, pw_len);

  u32 m[16] = { 0 };

  m[0] = md5apr1_magic0;
  m[1] = md5apr1_magic1;

  md5_update (&md5_ctx, m, 6);

  md5_update (&md5_ctx, s, salt_len);

  int pl;

  for (pl = pw_len; pl > 16; pl -= 16)
  {
    md5_update (&md5_ctx, final, 16);
  }

  truncate_block_4x4_le_S (final, pl);

  md5_update (&md5_ctx, final, pl);

  /* Then something really weird... */

  for (int i = pw_len; i != 0; i >>= 1)
  {
    u32 t[16] = { 0 };

    if (i & 1)
    {
      t[0] = 0;
    }
    else
    {
      t[0] = w[0] & 0xff;
    }

    md5_update (&md5_ctx, t, 1);
  }

  md5_final (&md5_ctx);

  tmps[gid].digest_buf[0] = md5_ctx.h[0];
  tmps[gid].digest_buf[1] = md5_ctx.h[1];
  tmps[gid].digest_buf[2] = md5_ctx.h[2];
  tmps[gid].digest_buf[3] = md5_ctx.h[3];
}

__kernel void m01600_loop (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  /**
   * digest
   */

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  u32 wpc_len[8];

  wpc_len[0] = 16     +        0 +      0 + pw_len;
  wpc_len[1] = pw_len +        0 +      0 + 16;
  wpc_len[2] = 16     + salt_len +      0 + pw_len;
  wpc_len[3] = pw_len + salt_len +      0 + 16;
  wpc_len[4] = 16     +        0 + pw_len + pw_len;
  wpc_len[5] = pw_len +        0 + pw_len + 16;
  wpc_len[6] = 16     + salt_len + pw_len + pw_len;
  wpc_len[7] = pw_len + salt_len + pw_len + 16;

  // largest possible wpc_len[7] is not enough because of zero buffer loop

  u32 wpc[8][64 + 64 + 64 + 64];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 8; i++)
  {
    u32 block_len = 0;

    if (i & 1)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }
    else
    {
      block_len += 16;
    }

    if (i & 2)
    {
      for (u32 j = 0; j < salt_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (s, j));
      }
    }

    if (i & 4)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }

    if (i & 1)
    {
      block_len += 16;
    }
    else
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 8; i++)
  {
    u32 *z = wpc[i] + ((wpc_len[i] / 64) * 16);

    truncate_block_16x4_le_S (z + 0, z + 4, z + 8, z + 12, wpc_len[i] & 63);
  }

  /**
   * loop
   */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 2 : 0;
    const u32 j7 = (j % 7) ? 4 : 0;

    const u32 pc = j1 + j3 + j7;

    if (j1)
    {
      MAYBE_VOLATILE const u32 off = wpc_len[pc] / 4;
      MAYBE_VOLATILE const u32 mod = wpc_len[pc] % 4;

      u32 *ptr = wpc[pc] + off - 4;

      switch (mod)
      {
        case 0:
          ptr[0] = digest[0];
          ptr[1] = digest[1];
          ptr[2] = digest[2];
          ptr[3] = digest[3];
          break;

        case 1:
          ptr[0] = (ptr[0] & 0xff)     | (digest[0] <<  8);
          ptr[1] = (digest[0] >> 24)   | (digest[1] <<  8);
          ptr[2] = (digest[1] >> 24)   | (digest[2] <<  8);
          ptr[3] = (digest[2] >> 24)   | (digest[3] <<  8);
          ptr[4] = (digest[3] >> 24);
          break;

        case 2:
          ptr[0] = (ptr[0] & 0xffff)   | (digest[0] << 16);
          ptr[1] = (digest[0] >> 16)   | (digest[1] << 16);
          ptr[2] = (digest[1] >> 16)   | (digest[2] << 16);
          ptr[3] = (digest[2] >> 16)   | (digest[3] << 16);
          ptr[4] = (digest[3] >> 16);
          break;

        case 3:
          ptr[0] = (ptr[0] & 0xffffff) | (digest[0] << 24);
          ptr[1] = (digest[0] >>  8)   | (digest[1] << 24);
          ptr[2] = (digest[1] >>  8)   | (digest[2] << 24);
          ptr[3] = (digest[2] >>  8)   | (digest[3] << 24);
          ptr[4] = (digest[3] >>  8);
          break;
      }
    }
    else
    {
      wpc[pc][0] = digest[0];
      wpc[pc][1] = digest[1];
      wpc[pc][2] = digest[2];
      wpc[pc][3] = digest[3];
    }

    md5_ctx_t md5_ctx;

    md5_init (&md5_ctx);

    md5_update (&md5_ctx, wpc[pc], wpc_len[pc]);

    md5_final (&md5_ctx);

    digest[0] = md5_ctx.h[0];
    digest[1] = md5_ctx.h[1];
    digest[2] = md5_ctx.h[2];
    digest[3] = md5_ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

__kernel void m01600_comp (KERN_ATTR_TMPS (md5crypt_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
