
/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

/*
Pseudocode:
1. sha256(sha256(password=masterkey)||keyfile) = argon.in
2. argon2(salt=transformseed, password=argon2.in) = argon2.out
2. sha512(masterseed||argon2.out||0x01) = final
3. sha512(0xFFFFFFFFFFFFFFFF||final) = out
4. hmac_sha256(init=out, data=header) = header_hmac
5. compare header_hmac to hash
*/

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#ifndef ARGON2_PARALLELISM
#define ARGON2_PARALLELISM 0
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

typedef struct keepass4
{
  u32 masterseed[8];
  u32 header[64];

  /* key-file handling */
  u32 keyfile_len;
  u32 keyfile[8];

} keepass4_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;

  keepass4_t keepass4;

} merged_options_t;

KERNEL_FQ KERNEL_FA void m34300_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  GLOBAL_AS const keepass4_t *keepass4 = &esalt_bufs[DIGESTS_OFFSET_HOST].keepass4;

  sha256_ctx_t ctx0;
  sha256_init (&ctx0);
  sha256_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
  sha256_final (&ctx0);

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  ctx.w0[0] = ctx0.h[0];
  ctx.w0[1] = ctx0.h[1];
  ctx.w0[2] = ctx0.h[2];
  ctx.w0[3] = ctx0.h[3];
  ctx.w1[0] = ctx0.h[4];
  ctx.w1[1] = ctx0.h[5];
  ctx.w1[2] = ctx0.h[6];
  ctx.w1[3] = ctx0.h[7];

  ctx.len = 32;

  if (keepass4->keyfile_len)
  {
    ctx.w2[0] = keepass4->keyfile[0];
    ctx.w2[1] = keepass4->keyfile[1];
    ctx.w2[2] = keepass4->keyfile[2];
    ctx.w2[3] = keepass4->keyfile[3];
    ctx.w3[0] = keepass4->keyfile[4];
    ctx.w3[1] = keepass4->keyfile[5];
    ctx.w3[2] = keepass4->keyfile[6];
    ctx.w3[3] = keepass4->keyfile[7];

    ctx.len += 32;

    sha256_transform (ctx.w0, ctx.w1, ctx.w2, ctx.w3, ctx.h);

    ctx.w0[0] = 0;
    ctx.w0[1] = 0;
    ctx.w0[2] = 0;
    ctx.w0[3] = 0;
    ctx.w1[0] = 0;
    ctx.w1[1] = 0;
    ctx.w1[2] = 0;
    ctx.w1[3] = 0;
    ctx.w2[0] = 0;
    ctx.w2[1] = 0;
    ctx.w2[2] = 0;
    ctx.w2[3] = 0;
    ctx.w3[0] = 0;
    ctx.w3[1] = 0;
    ctx.w3[2] = 0;
    ctx.w3[3] = 0;
  }

  sha256_final (&ctx);

  pw_t pw;

  pw.i[ 0] = hc_swap32_S (ctx.h[0]);
  pw.i[ 1] = hc_swap32_S (ctx.h[1]);
  pw.i[ 2] = hc_swap32_S (ctx.h[2]);
  pw.i[ 3] = hc_swap32_S (ctx.h[3]);
  pw.i[ 4] = hc_swap32_S (ctx.h[4]);
  pw.i[ 5] = hc_swap32_S (ctx.h[5]);
  pw.i[ 6] = hc_swap32_S (ctx.h[6]);
  pw.i[ 7] = hc_swap32_S (ctx.h[7]);
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;

  pw.pw_len = 32; // output of sha256 is always 32 bytes

  argon2_init_pg (&pw, &salt_bufs[SALT_POS_HOST], &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m34300_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #if ARGON2_PARALLELISM > 0
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #if ARGON2_PARALLELISM > 0
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < argon2_options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m34300_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  GLOBAL_AS const keepass4_t *keepass4 = &esalt_bufs[DIGESTS_OFFSET_HOST].keepass4;

  u32 out[8];

  argon2_final (argon2_block, &argon2_options, out);

  sha512_ctx_t ctx;
  sha512_init (&ctx);

  ctx.w0[0] = hc_swap32_S (keepass4->masterseed[0]);
  ctx.w0[1] = hc_swap32_S (keepass4->masterseed[1]);
  ctx.w0[2] = hc_swap32_S (keepass4->masterseed[2]);
  ctx.w0[3] = hc_swap32_S (keepass4->masterseed[3]);
  ctx.w1[0] = hc_swap32_S (keepass4->masterseed[4]);
  ctx.w1[1] = hc_swap32_S (keepass4->masterseed[5]);
  ctx.w1[2] = hc_swap32_S (keepass4->masterseed[6]);
  ctx.w1[3] = hc_swap32_S (keepass4->masterseed[7]);
  ctx.w2[0] = hc_swap32_S (out[0]);
  ctx.w2[1] = hc_swap32_S (out[1]);
  ctx.w2[2] = hc_swap32_S (out[2]);
  ctx.w2[3] = hc_swap32_S (out[3]);
  ctx.w3[0] = hc_swap32_S (out[4]);
  ctx.w3[1] = hc_swap32_S (out[5]);
  ctx.w3[2] = hc_swap32_S (out[6]);
  ctx.w3[3] = hc_swap32_S (out[7]);
  ctx.w4[0] = 0x01000000;

  ctx.len = 32 + 32 + 1;

  sha512_final (&ctx);

  sha512_ctx_t ctx2;
  sha512_init (&ctx2);

  ctx2.w0[0] = 0xffffffff;
  ctx2.w0[1] = 0xffffffff;
  ctx2.w0[2] = h32_from_64_S (ctx.h[0]);
  ctx2.w0[3] = l32_from_64_S (ctx.h[0]);
  ctx2.w1[0] = h32_from_64_S (ctx.h[1]);
  ctx2.w1[1] = l32_from_64_S (ctx.h[1]);
  ctx2.w1[2] = h32_from_64_S (ctx.h[2]);
  ctx2.w1[3] = l32_from_64_S (ctx.h[2]);
  ctx2.w2[0] = h32_from_64_S (ctx.h[3]);
  ctx2.w2[1] = l32_from_64_S (ctx.h[3]);
  ctx2.w2[2] = h32_from_64_S (ctx.h[4]);
  ctx2.w2[3] = l32_from_64_S (ctx.h[4]);
  ctx2.w3[0] = h32_from_64_S (ctx.h[5]);
  ctx2.w3[1] = l32_from_64_S (ctx.h[5]);
  ctx2.w3[2] = h32_from_64_S (ctx.h[6]);
  ctx2.w3[3] = l32_from_64_S (ctx.h[6]);
  ctx2.w4[0] = h32_from_64_S (ctx.h[7]);
  ctx2.w4[1] = l32_from_64_S (ctx.h[7]);

  ctx2.len = 8 + 64;

  sha512_final (&ctx2);

  u32 outu32[16];

  outu32[ 0] = h32_from_64_S (ctx2.h[0]);
  outu32[ 1] = l32_from_64_S (ctx2.h[0]);
  outu32[ 2] = h32_from_64_S (ctx2.h[1]);
  outu32[ 3] = l32_from_64_S (ctx2.h[1]);
  outu32[ 4] = h32_from_64_S (ctx2.h[2]);
  outu32[ 5] = l32_from_64_S (ctx2.h[2]);
  outu32[ 6] = h32_from_64_S (ctx2.h[3]);
  outu32[ 7] = l32_from_64_S (ctx2.h[3]);
  outu32[ 8] = h32_from_64_S (ctx2.h[4]);
  outu32[ 9] = l32_from_64_S (ctx2.h[4]);
  outu32[10] = h32_from_64_S (ctx2.h[5]);
  outu32[11] = l32_from_64_S (ctx2.h[5]);
  outu32[12] = h32_from_64_S (ctx2.h[6]);
  outu32[13] = l32_from_64_S (ctx2.h[6]);
  outu32[14] = h32_from_64_S (ctx2.h[7]);
  outu32[15] = l32_from_64_S (ctx2.h[7]);

  sha256_hmac_ctx_t ctx3;
  sha256_hmac_init (&ctx3, outu32, 64);
  sha256_hmac_update_global_swap (&ctx3, keepass4->header, 253);
  sha256_hmac_final (&ctx3);

  const u32 r0 = hc_swap32_S (ctx3.opad.h[0]);
  const u32 r1 = hc_swap32_S (ctx3.opad.h[1]);
  const u32 r2 = hc_swap32_S (ctx3.opad.h[2]);
  const u32 r3 = hc_swap32_S (ctx3.opad.h[3]);

  #define il_pos 0

  #include COMPARE_M
}
