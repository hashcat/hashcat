/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef PCFG_KERN_ATTR
#define PCFG_KERN_ATTR KERN_ATTR_PCFG ()
#endif

#ifndef PCFG_HASH_BLKWORDS
#define PCFG_HASH_BLKWORDS 16
#endif

#ifndef PCFG_PT_CASE
#define PCFG_PT_CASE 0
#endif

#define PCFG_PT_CASE_UPPER 1
#define PCFG_PT_CASE_LOWER 2

DECLSPEC void pcfg_pt_case (MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 len)
{
  #if PCFG_PT_CASE == PCFG_PT_CASE_UPPER

  for (u32 i = 0; i < len; i++)
  {
    const u32 c = pcfg_get_byte (w, i);

    if ((c >= 'a') && (c <= 'z')) pcfg_put_byte (w, i, c - 32);
  }

  #elif PCFG_PT_CASE == PCFG_PT_CASE_LOWER

  for (u32 i = 0; i < len; i++)
  {
    const u32 c = pcfg_get_byte (w, i);

    if ((c >= 'A') && (c <= 'Z')) pcfg_put_byte (w, i, c + 32);
  }

  #endif
}

#define PCFG_ARRAY_WORDS (((PCFG_DEV_WORDS + PCFG_HASH_BLKWORDS - 1) / PCFG_HASH_BLKWORDS) * PCFG_HASH_BLKWORDS)

#ifndef PCFG_HASH_SHARED_DECL
#define PCFG_HASH_SHARED_DECL
#endif

#ifndef PCFG_HASH_SHARED_BIND
#define PCFG_HASH_SHARED_BIND(hc)
#endif

KERNEL_FQ KERNEL_FA void PCFG_KERNEL_MXX (PCFG_KERN_ATTR)
{

  const u64 lid = get_local_id (0);

  MAYBE_UNUSED const u64 lsz = get_local_size (0);
  const u64 tid = get_global_id (0);

  PCFG_HASH_SHARED_DECL

  if (tid >= GID_CNT) return;

  u64 gid  = 0;
  u32 lane = 0;

  if (PCFG_LANE_STRIDE > 0)
  {

    gid  = tid / PCFG_DEV_LANES;
    lane = (u32) (tid % PCFG_DEV_LANES);
  }
  else
  {

    const u64 wave = tid / PCFG_DEV_WARP;

    gid  = pcfg_wmap[wave];
    lane = (u32) (((wave - pcfg_cells[gid].wave_base) * PCFG_DEV_WARP) + (tid % PCFG_DEV_WARP));
  }

  LOCAL_VK pcfg_cell_t s_cells[1];
  LOCAL_VK u32         s_digit[PCFG_DEV_GROUP][PCFG_DEV_MAXSLOT + 1];

  const u64 wid = 0;

  if ((pcfg_cells[gid].slot_cnt > 0) && ((((pcfg_cells[gid].flags & PCFG_CELL_VARLEN) != 0) != (PCFG_DEV_VARLEN != 0)))) return;

  const u32 wide = pcfg_cells[gid].rect;

  const u32 rect = (wide > 0) ? wide : 1;

  const u32 wide_blk = pcfg_cells[gid].blk;

  const u32 blk = (wide_blk > 0) ? wide_blk : 1;
  const u32 beg = lane * blk;

  if (beg >= rect) return;

  const u32 end = ((beg + blk) < rect) ? (beg + blk) : rect;

  s_cells[wid] = pcfg_cells[gid];

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len > PCFG_DEV_MAXBYTE)
  {
    if (lane > 0) return;

    pcfg_hash_ctx_t hc;

    PCFG_HASH_SHARED_BIND (&hc)

    pcfg_hash_init (&hc, salt_bufs, SALT_POS_HOST, esalt_bufs, digests_buf, DIGESTS_OFFSET_HOST);

    u32 dgst[4];

    if (pcfg_hash_global (&hc, pws[gid].i, pw_len, dgst) == true)
    {

      const u32 il_pos = 0;

      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_M_SCALAR (r0, r1, r2, r3);
    }

    return;
  }

  u32 w[PCFG_ARRAY_WORDS];

  #if PCFG_DEV_VARLEN

  for (u32 i = 0; i < PCFG_ARRAY_WORDS; i++) w[i] = 0;

  #else

  const u32 nblk = (pw_len / (PCFG_HASH_BLKWORDS * 4)) + 1;

  for (u32 i = 0; i < (nblk * PCFG_HASH_BLKWORDS); i++) w[i] = 0;

  #endif

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) w[idx] = pws[gid].i[idx];

  pcfg_hash_ctx_t hc;

  PCFG_HASH_SHARED_BIND (&hc)

  pcfg_hash_init  (&hc, salt_bufs, SALT_POS_HOST, esalt_bufs, digests_buf, DIGESTS_OFFSET_HOST);

  pcfg_hash_setup (&hc, w, pw_len);

  if (pcfg_odo_seed (&s_cells[wid], beg, s_digit[lid]) == false) return;

  #if PCFG_DEV_VARLEN

  u32 cur_len = pw_len;

  u32 nxt = (s_cells[wid].slot_cnt > 0) ? pcfg_write (&s_cells[wid], pcfg_pool, s_digit[lid], w) : pw_len;

  for (u32 il_pos = beg; il_pos < end; il_pos++)
  {

    for (u32 k = nxt; k <= cur_len; k++) pcfg_put_byte (w, k, 0);

    cur_len = nxt;

    pcfg_pt_case (w, cur_len);

    u32 dgst[4];

    if (pcfg_hash (&hc, w, cur_len, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_M_SCALAR (r0, r1, r2, r3);
    }

    if ((il_pos + 1) == end) break;

    const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

    if (from < 0) break;

    nxt = pcfg_write_from (&s_cells[wid], pcfg_pool, s_digit[lid], w, (u32) from);
  }

  #else

  pcfg_write (&s_cells[wid], pcfg_pool, s_digit[lid], w);

  for (u32 il_pos = beg; il_pos < end; il_pos++)
  {
    pcfg_pt_case (w, pw_len);

    u32 dgst[4];

    if (pcfg_hash (&hc, w, pw_len, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_M_SCALAR (r0, r1, r2, r3);
    }

    if ((il_pos + 1) == end) break;

    const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

    if (from < 0) break;

    pcfg_write_from (&s_cells[wid], pcfg_pool, s_digit[lid], w, (u32) from);
  }

  #endif
}

KERNEL_FQ KERNEL_FA void PCFG_KERNEL_SXX (PCFG_KERN_ATTR)
{

  const u64 lid = get_local_id (0);

  MAYBE_UNUSED const u64 lsz = get_local_size (0);
  const u64 tid = get_global_id (0);

  PCFG_HASH_SHARED_DECL

  if (tid >= GID_CNT) return;

  u64 gid  = 0;
  u32 lane = 0;

  if (PCFG_LANE_STRIDE > 0)
  {

    gid  = tid / PCFG_DEV_LANES;
    lane = (u32) (tid % PCFG_DEV_LANES);
  }
  else
  {

    const u64 wave = tid / PCFG_DEV_WARP;

    gid  = pcfg_wmap[wave];
    lane = (u32) (((wave - pcfg_cells[gid].wave_base) * PCFG_DEV_WARP) + (tid % PCFG_DEV_WARP));
  }

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  LOCAL_VK pcfg_cell_t s_cells[1];
  LOCAL_VK u32         s_digit[PCFG_DEV_GROUP][PCFG_DEV_MAXSLOT + 1];

  const u64 wid = 0;

  if ((pcfg_cells[gid].slot_cnt > 0) && ((((pcfg_cells[gid].flags & PCFG_CELL_VARLEN) != 0) != (PCFG_DEV_VARLEN != 0)))) return;

  const u32 wide = pcfg_cells[gid].rect;

  const u32 rect = (wide > 0) ? wide : 1;

  const u32 wide_blk = pcfg_cells[gid].blk;

  const u32 blk = (wide_blk > 0) ? wide_blk : 1;
  const u32 beg = lane * blk;

  if (beg >= rect) return;

  const u32 end = ((beg + blk) < rect) ? (beg + blk) : rect;

  s_cells[wid] = pcfg_cells[gid];

  const u32 pw_len = pws[gid].pw_len;

  if (pw_len > PCFG_DEV_MAXBYTE)
  {
    if (lane > 0) return;

    pcfg_hash_ctx_t hc;

    PCFG_HASH_SHARED_BIND (&hc)

    pcfg_hash_init (&hc, salt_bufs, SALT_POS_HOST, esalt_bufs, digests_buf, DIGESTS_OFFSET_HOST);

    u32 dgst[4];

    if (pcfg_hash_global (&hc, pws[gid].i, pw_len, dgst) == true)
    {

      const u32 il_pos = 0;

      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_S_SCALAR (r0, r1, r2, r3);
    }

    return;
  }

  u32 w[PCFG_ARRAY_WORDS];

  #if PCFG_DEV_VARLEN

  for (u32 i = 0; i < PCFG_ARRAY_WORDS; i++) w[i] = 0;

  #else

  const u32 nblk = (pw_len / (PCFG_HASH_BLKWORDS * 4)) + 1;

  for (u32 i = 0; i < (nblk * PCFG_HASH_BLKWORDS); i++) w[i] = 0;

  #endif

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1) w[idx] = pws[gid].i[idx];

  pcfg_hash_ctx_t hc;

  PCFG_HASH_SHARED_BIND (&hc)

  pcfg_hash_init  (&hc, salt_bufs, SALT_POS_HOST, esalt_bufs, digests_buf, DIGESTS_OFFSET_HOST);

  pcfg_hash_setup (&hc, w, pw_len);

  if (pcfg_odo_seed (&s_cells[wid], beg, s_digit[lid]) == false) return;

  #if PCFG_DEV_VARLEN

  u32 cur_len = pw_len;

  u32 nxt = (s_cells[wid].slot_cnt > 0) ? pcfg_write (&s_cells[wid], pcfg_pool, s_digit[lid], w) : pw_len;

  for (u32 il_pos = beg; il_pos < end; il_pos++)
  {

    for (u32 k = nxt; k <= cur_len; k++) pcfg_put_byte (w, k, 0);

    cur_len = nxt;

    pcfg_pt_case (w, cur_len);

    u32 dgst[4];

    if (pcfg_hash (&hc, w, cur_len, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_S_SCALAR (r0, r1, r2, r3);
    }

    if ((il_pos + 1) == end) break;

    const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

    if (from < 0) break;

    nxt = pcfg_write_from (&s_cells[wid], pcfg_pool, s_digit[lid], w, (u32) from);
  }

  #else

  pcfg_write (&s_cells[wid], pcfg_pool, s_digit[lid], w);

  for (u32 il_pos = beg; il_pos < end; il_pos++)
  {
    pcfg_pt_case (w, pw_len);

    u32 dgst[4];

    if (pcfg_hash (&hc, w, pw_len, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_S_SCALAR (r0, r1, r2, r3);
    }

    if ((il_pos + 1) == end) break;

    const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

    if (from < 0) break;

    pcfg_write_from (&s_cells[wid], pcfg_pool, s_digit[lid], w, (u32) from);
  }

  #endif
}
