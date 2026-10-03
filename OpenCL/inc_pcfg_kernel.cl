/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef PCFG_KERN_ATTR
#define PCFG_KERN_ATTR KERN_ATTR_PCFG ()
#endif

// The rule engine is compiled in only where the rules are applied on the device. A run without them
// builds the kernel it built before this existed, which is what keeps the cell's speed and what keeps
// the kernel inside what Metal's compiler will take.

#if PCFG_DEV_RULES
#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#endif
#endif

#ifndef PCFG_HASH_BLKWORDS
#define PCFG_HASH_BLKWORDS 16
#endif

// hashcat settles whether the escape is walked in this kernel and hands it over as a build option,
// so a run with no escape to walk compiles none of the walk below.
//
// The default walks it. A kernel built without the walk takes a cell of the escape for a cell of the
// grammar, which has no slots to write and so hashes the base word once per candidate, and it does
// that quietly. Compiling the walk in costs code where it is not needed and answers correctly where
// the option did not arrive.

#ifndef PCFG_DEV_OMEN
#define PCFG_DEV_OMEN 1
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

#if PCFG_DEV_OMEN

#include "inc_pcfg_omen.cl"

#endif // PCFG_DEV_OMEN

KERNEL_FQ KERNEL_FA void PCFG_KERNEL_MXX (PCFG_KERN_ATTR)
{
  PCFG_POOL_KERN (pcfg_pool_v)

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

    #if PCFG_DEV_RULES

    // With the rules inside the engine this word has nowhere to go. Hashing it here would report a
    // candidate no rule was applied to, and the run tries none of those. A rule is no use to it
    // either: the bound under the rules is 255 bytes, which is the length apply_rules () holds its
    // input to, and this word is longer than that.

    return;

    #endif

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

  // A cell is the grammar's or the escape's and never both, so the two halves that produce a candidate
  // are the ones they always were and only the tail is shared. The tail is where the mode's hash gets
  // inlined, and a second copy of it in the same kernel is a second copy the compiler has to hold: on
  // Metal, for a mode whose hash is a whole AES, holding two aborted the compiler inside
  // CloneBasicBlock and took MTLCompilerService down with it.

  #if PCFG_DEV_OMEN

  const bool omen = ((s_cells[wid].flags & PCFG_CELL_OMEN) != 0);

  pcfg_omen_model_t om;
  pcfg_omen_walk_t  ow;

  int omen_cost = 0;

  #else

  const bool omen = false;

  #endif

  #if PCFG_DEV_VARLEN

  u32 cur_len = pw_len;
  u32 nxt     = pw_len;

  #endif

  if (omen == true)
  {
    #if PCFG_DEV_OMEN

    omen_cost           = (int) s_cells[wid].slots[0].pool_off;
    const u64 rank_base = ((u64) s_cells[wid].slots[0].digit << 32) | (u64) s_cells[wid].slots[0].radix;
    const u32 dir_at    = s_cells[wid].slots[0].packed;
    const u32 model_idx = s_cells[wid].slots[1].pool_off;

    pcfg_omen_model (PCFG_POOL_REF (pcfg_pool_v), dir_at, model_idx, &om);

    pcfg_omen_land_t ld;

    if (s_cells[wid].slots[2].digit != 0)
    {
      ld.li   = s_cells[wid].slots[1].radix;
      ld.sc   = s_cells[wid].slots[1].digit;
      ld.i    = s_cells[wid].slots[1].packed;
      ld.rank = ((u64) s_cells[wid].slots[2].radix << 32) | (u64) s_cells[wid].slots[2].pool_off;
    }
    else
    {
      // No landing came with the cell, so the walk starts at the head of the model and spends the
      // whole rank itself, which is what every lane used to do.

      ld.li   = 0;
      ld.sc   = 0;
      ld.i    = pcfg_pool_u32 (PCFG_POOL_REF (pcfg_pool_v), om.start_lvl);
      ld.rank = rank_base;
    }

    // The rank is spent once, by the host, and every candidate after it is a step of the walk

    if (pcfg_omen_seed (PCFG_POOL_REF (pcfg_pool_v), &om, omen_cost, &ld, beg, &ow) == false) return;

    #endif
  }
  else
  {
    if (pcfg_odo_seed (&s_cells[wid], beg, s_digit[lid]) == false) return;

    #if PCFG_DEV_VARLEN

    nxt = (s_cells[wid].slot_cnt > 0) ? pcfg_write (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w) : pw_len;

    #else

    pcfg_write (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w);

    #endif
  }

  for (u32 cell_pos = beg; cell_pos < end; cell_pos++)
  {
    u32 clen = 0;

    if (omen == true)
    {
      #if PCFG_DEV_OMEN

      if (cell_pos > beg)
      {
        if (pcfg_omen_step (PCFG_POOL_REF (pcfg_pool_v), &om, omen_cost, &ow) == false) return;
      }

      const int len = pcfg_omen_emit (PCFG_POOL_REF (pcfg_pool_v), &om, &ow, w, PCFG_ARRAY_WORDS, PCFG_DEV_MAXBYTE);

      if (len < 0) continue;

      clen = (u32) len;

      // The escape is not one length, so this is the one path that sets the hash up per candidate.

      pcfg_hash_setup (&hc, w, clen);

      #endif
    }
    else
    {
      // The odometer is stepped at the head rather than the tail, so that the tail can be shared.

      if (cell_pos > beg)
      {
        const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

        if (from < 0) break;

        #if PCFG_DEV_VARLEN

        nxt = pcfg_write_from (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w, (u32) from);

        #else

        pcfg_write_from (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w, (u32) from);

        #endif
      }

      #if PCFG_DEV_VARLEN

      for (u32 k = nxt; k <= cur_len; k++) pcfg_put_byte (w, k, 0);

      cur_len = nxt;

      clen = cur_len;

      #else

      clen = pw_len;

      #endif
    }

    // The mode's own case conversion belongs to the candidate the cell made, before any rule sees it.
    // That is the order every other attack has: the host cases the word it hands over, and the rules run
    // on the device after that.

    pcfg_pt_case (w, clen);

    #if PCFG_DEV_RULES

    // The cell is walked on the device and the rules amplify what it made, which is the arrangement the
    // straight kernel has for a word list: il_pos names the rule, and the host stages one chunk of them
    // into constant memory per launch. The step inside the cell cannot also be il_pos, so it rides in the
    // spare word of the crack record, because naming the candidate again needs both.
    //
    // The rule is applied to a copy. The odometer rewrites only the suffix that changed on the next step,
    // so a rule that edited w in place would leave the step after it building on a candidate that was
    // never in the grammar.

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
    {
      u32 r[PCFG_ARRAY_WORDS];

      for (u32 i = 0; i < PCFG_ARRAY_WORDS; i++) r[i] = w[i];

      const int rlen = apply_rules (rules_buf[il_pos].cmds, r, (int) clen);

      // A rule that rejects answers below one, and a rule that empties the candidate answers zero.
      // Neither is something this run can try. A longer one needs no guard of its own: the array is
      // PW_MAX wide here, and at that width the hash is the streaming one, which needs no room inside it.

      if (rlen < 1) continue;

      // Bytes past the new length have to be zero, and a rule that shortened the candidate left the old
      // ones behind. Past the old length the array was zero already, so the stretch between the two is
      // the only thing that can hold anything, and a rule that lengthened leaves nothing to do here.

      for (u32 k = (u32) rlen; k < clen; k++) pcfg_put_byte (r, k, 0);

      // The rule decides the length, so the hash is set up per candidate the way the escape's own are,
      // rather than once per cell.

      pcfg_hash_setup (&hc, r, (u32) rlen);

      u32 dgst[4];

      if (pcfg_hash (&hc, r, (u32) rlen, dgst) == true)
      {
        const u32 r0 = dgst[0];
        const u32 r1 = dgst[1];
        const u32 r2 = dgst[2];
        const u32 r3 = dgst[3];

        COMPARE_M_SCALAR_EXTRA (r0, r1, r2, r3, cell_pos, 0);
      }
    }

    #else

    const u32 il_pos = cell_pos;

    u32 dgst[4];

    if (pcfg_hash (&hc, w, clen, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_M_SCALAR (r0, r1, r2, r3);
    }

    #endif
  }
}

KERNEL_FQ KERNEL_FA void PCFG_KERNEL_SXX (PCFG_KERN_ATTR)
{
  PCFG_POOL_KERN (pcfg_pool_v)

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

    #if PCFG_DEV_RULES

    // With the rules inside the engine this word has nowhere to go. Hashing it here would report a
    // candidate no rule was applied to, and the run tries none of those. A rule is no use to it
    // either: the bound under the rules is 255 bytes, which is the length apply_rules () holds its
    // input to, and this word is longer than that.

    return;

    #endif

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

  // A cell is the grammar's or the escape's and never both, so the two halves that produce a candidate
  // are the ones they always were and only the tail is shared. The tail is where the mode's hash gets
  // inlined, and a second copy of it in the same kernel is a second copy the compiler has to hold: on
  // Metal, for a mode whose hash is a whole AES, holding two aborted the compiler inside
  // CloneBasicBlock and took MTLCompilerService down with it.

  #if PCFG_DEV_OMEN

  const bool omen = ((s_cells[wid].flags & PCFG_CELL_OMEN) != 0);

  pcfg_omen_model_t om;
  pcfg_omen_walk_t  ow;

  int omen_cost = 0;

  #else

  const bool omen = false;

  #endif

  #if PCFG_DEV_VARLEN

  u32 cur_len = pw_len;
  u32 nxt     = pw_len;

  #endif

  if (omen == true)
  {
    #if PCFG_DEV_OMEN

    omen_cost           = (int) s_cells[wid].slots[0].pool_off;
    const u64 rank_base = ((u64) s_cells[wid].slots[0].digit << 32) | (u64) s_cells[wid].slots[0].radix;
    const u32 dir_at    = s_cells[wid].slots[0].packed;
    const u32 model_idx = s_cells[wid].slots[1].pool_off;

    pcfg_omen_model (PCFG_POOL_REF (pcfg_pool_v), dir_at, model_idx, &om);

    pcfg_omen_land_t ld;

    if (s_cells[wid].slots[2].digit != 0)
    {
      ld.li   = s_cells[wid].slots[1].radix;
      ld.sc   = s_cells[wid].slots[1].digit;
      ld.i    = s_cells[wid].slots[1].packed;
      ld.rank = ((u64) s_cells[wid].slots[2].radix << 32) | (u64) s_cells[wid].slots[2].pool_off;
    }
    else
    {
      // No landing came with the cell, so the walk starts at the head of the model and spends the
      // whole rank itself, which is what every lane used to do.

      ld.li   = 0;
      ld.sc   = 0;
      ld.i    = pcfg_pool_u32 (PCFG_POOL_REF (pcfg_pool_v), om.start_lvl);
      ld.rank = rank_base;
    }

    // The rank is spent once, by the host, and every candidate after it is a step of the walk

    if (pcfg_omen_seed (PCFG_POOL_REF (pcfg_pool_v), &om, omen_cost, &ld, beg, &ow) == false) return;

    #endif
  }
  else
  {
    if (pcfg_odo_seed (&s_cells[wid], beg, s_digit[lid]) == false) return;

    #if PCFG_DEV_VARLEN

    nxt = (s_cells[wid].slot_cnt > 0) ? pcfg_write (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w) : pw_len;

    #else

    pcfg_write (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w);

    #endif
  }

  for (u32 cell_pos = beg; cell_pos < end; cell_pos++)
  {
    u32 clen = 0;

    if (omen == true)
    {
      #if PCFG_DEV_OMEN

      if (cell_pos > beg)
      {
        if (pcfg_omen_step (PCFG_POOL_REF (pcfg_pool_v), &om, omen_cost, &ow) == false) return;
      }

      const int len = pcfg_omen_emit (PCFG_POOL_REF (pcfg_pool_v), &om, &ow, w, PCFG_ARRAY_WORDS, PCFG_DEV_MAXBYTE);

      if (len < 0) continue;

      clen = (u32) len;

      // The escape is not one length, so this is the one path that sets the hash up per candidate.

      pcfg_hash_setup (&hc, w, clen);

      #endif
    }
    else
    {
      // The odometer is stepped at the head rather than the tail, so that the tail can be shared.

      if (cell_pos > beg)
      {
        const int from = pcfg_odo_next (&s_cells[wid], s_digit[lid]);

        if (from < 0) break;

        #if PCFG_DEV_VARLEN

        nxt = pcfg_write_from (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w, (u32) from);

        #else

        pcfg_write_from (&s_cells[wid], PCFG_POOL_REF (pcfg_pool_v), pws[gid].i, s_digit[lid], w, (u32) from);

        #endif
      }

      #if PCFG_DEV_VARLEN

      for (u32 k = nxt; k <= cur_len; k++) pcfg_put_byte (w, k, 0);

      cur_len = nxt;

      clen = cur_len;

      #else

      clen = pw_len;

      #endif
    }

    // The mode's own case conversion belongs to the candidate the cell made, before any rule sees it.
    // That is the order every other attack has: the host cases the word it hands over, and the rules run
    // on the device after that.

    pcfg_pt_case (w, clen);

    #if PCFG_DEV_RULES

    // The same arrangement as PCFG_KERNEL_MXX above, including why the step inside the cell rides in the
    // crack record's spare word and why the rule works on a copy.

    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
    {
      u32 r[PCFG_ARRAY_WORDS];

      for (u32 i = 0; i < PCFG_ARRAY_WORDS; i++) r[i] = w[i];

      const int rlen = apply_rules (rules_buf[il_pos].cmds, r, (int) clen);

      // A rule that rejects answers below one, and a rule that empties the candidate answers zero.
      // Neither is something this run can try. A longer one needs no guard of its own: the array is
      // PW_MAX wide here, and at that width the hash is the streaming one, which needs no room inside it.

      if (rlen < 1) continue;

      // Bytes past the new length have to be zero, and a rule that shortened the candidate left the old
      // ones behind. Past the old length the array was zero already, so the stretch between the two is
      // the only thing that can hold anything, and a rule that lengthened leaves nothing to do here.

      for (u32 k = (u32) rlen; k < clen; k++) pcfg_put_byte (r, k, 0);

      // The rule decides the length, so the hash is set up per candidate the way the escape's own are,
      // rather than once per cell.

      pcfg_hash_setup (&hc, r, (u32) rlen);

      u32 dgst[4];

      if (pcfg_hash (&hc, r, (u32) rlen, dgst) == true)
      {
        const u32 r0 = dgst[0];
        const u32 r1 = dgst[1];
        const u32 r2 = dgst[2];
        const u32 r3 = dgst[3];

        COMPARE_S_SCALAR_EXTRA (r0, r1, r2, r3, cell_pos, 0);
      }
    }

    #else

    const u32 il_pos = cell_pos;

    u32 dgst[4];

    if (pcfg_hash (&hc, w, clen, dgst) == true)
    {
      const u32 r0 = dgst[0];
      const u32 r1 = dgst[1];
      const u32 r2 = dgst[2];
      const u32 r3 = dgst[3];

      COMPARE_S_SCALAR (r0, r1, r2, r3);
    }

    #endif
  }
}
