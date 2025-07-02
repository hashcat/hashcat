
/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4]; // just something for now

} argon2_tmp_t;

typedef struct argon2_extra
{
#ifndef ARGON2_TMP_ELEM
#define ARGON2_TMP_ELEM 1
#endif

  argon2_block_t blocks[ARGON2_TMP_ELEM];

} argon2_extra_t;

KERNEL_FQ KERNEL_FA void m34000_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS argon2_extra_t *V;

  switch (gm4)
  {
    case 0: V = (GLOBAL_AS argon2_extra_t *) d_extra0_buf; break;
    case 1: V = (GLOBAL_AS argon2_extra_t *) d_extra1_buf; break;
    case 2: V = (GLOBAL_AS argon2_extra_t *) d_extra2_buf; break;
    case 3: V = (GLOBAL_AS argon2_extra_t *) d_extra3_buf; break;
  }

  GLOBAL_AS argon2_extra_t *argon2_extra = V + gd4;

  const argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  argon2_init (&pws[gid], &salt_bufs[SALT_POS_HOST], &options, argon2_extra->blocks);
}

KERNEL_FQ KERNEL_FA void m34000_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS argon2_extra_t *V;

  switch (bm4)
  {
    case 0: V = (GLOBAL_AS argon2_extra_t *) d_extra0_buf; break;
    case 1: V = (GLOBAL_AS argon2_extra_t *) d_extra1_buf; break;
    case 2: V = (GLOBAL_AS argon2_extra_t *) d_extra2_buf; break;
    case 3: V = (GLOBAL_AS argon2_extra_t *) d_extra3_buf; break;
  }

  GLOBAL_AS argon2_extra_t *argon2_extra = V + bd4;

  argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  options.parallelism = ARGON2_PARALLELISM;

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_extra->blocks, &options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
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

KERNEL_FQ KERNEL_FA void m34000_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS argon2_extra_t *V;

  switch (gm4)
  {
    case 0: V = (GLOBAL_AS argon2_extra_t *) d_extra0_buf; break;
    case 1: V = (GLOBAL_AS argon2_extra_t *) d_extra1_buf; break;
    case 2: V = (GLOBAL_AS argon2_extra_t *) d_extra2_buf; break;
    case 3: V = (GLOBAL_AS argon2_extra_t *) d_extra3_buf; break;
  }

  GLOBAL_AS argon2_extra_t *argon2_extra = V + gd4;

  u32 out[8];

  const argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  argon2_final (argon2_extra->blocks, &options, out);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #include COMPARE_M
}
