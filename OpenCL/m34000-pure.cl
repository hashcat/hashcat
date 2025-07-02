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
#ifndef ARGON2_TMP_ELEM
#define ARGON2_TMP_ELEM 1
#endif

  argon2_block_t blocks[ARGON2_TMP_ELEM];

} argon2_tmp_t;

KERNEL_FQ void m34000_init (_KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  argon2_init (&pws[gid], &salt_bufs[SALT_POS_HOST], &options, tmps[gid].blocks);
}

KERNEL_FQ void m34000_loop (_KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 gid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (gid >= GID_CNT) return;

  argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  options.parallelism = ARGON2_PARALLELISM;

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < options.parallelism; pos.lane += lsz)
    {
      argon2_fill_segment (tmps[gid].blocks, &options, &pos);
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

KERNEL_FQ void m34000_comp ( _KERN_ATTR_TMPS_ESALT (argon2_tmp_t, argon2_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out[8];

  const argon2_options_t options = esalt_bufs[DIGESTS_OFFSET_HOST];

  argon2_final (tmps[gid].blocks, &options, out);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #include COMPARE_M
}
