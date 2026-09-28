/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

typedef struct iclass_state
{
  u16 t;
  u8  l;
  u8  r;
  u8  b;
} iclass_state_t;

DECLSPEC iclass_state_t iclass_successor (PRIVATE_AS const u8 *k, const iclass_state_t s, const u8 y)
{
  const u8 r0 = (s.r >> 7) & 1;
  const u8 r4 = (s.r >> 3) & 1;
  const u8 r7 =  s.r        & 1;

  const u8 Tt = (u8) (((s.t >> 15) & 1) ^ ((s.t >> 14) & 1)
             ^ ((s.t >> 10) & 1) ^ ((s.t >>  8) & 1)
             ^ ((s.t >>  5) & 1) ^ ((s.t >>  4) & 1)
             ^ ((s.t >>  1) & 1) ^ ( s.t        & 1));

  const u8 Bt = (u8) (((s.b >> 6) & 1) ^ ((s.b >> 5) & 1)
             ^ ((s.b >> 4) & 1) ^ ( s.b        & 1));

  iclass_state_t ns;

  ns.t = (u16) ((s.t >> 1) | ((u16) ((Tt ^ r0 ^ r4) & 1) << 15));
  ns.b = (u8)  ((s.b >> 1) | ((u8)  ((Bt ^ r7)      & 1) << 7));

  const u8 r1 = (s.r >> 6) & 1;
  const u8 r2 = (s.r >> 5) & 1;
  const u8 r3 = (s.r >> 4) & 1;
  const u8 r5 = (s.r >> 2) & 1;
  const u8 r6 = (s.r >> 1) & 1;

  const u8 z0 = (u8) ((r0 & r2) ^ (r1 & (r3 ^ 1)) ^ (r2 | r4));
  const u8 z1 = (u8) ((r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ Tt ^ y);
  const u8 z2 = (u8) ((r3 & (r5 ^ 1)) ^ (r4 & r6) ^ r7 ^ Tt);

  const u8 sel = ((z0 & 1) << 2) | ((z1 & 1) << 1) | (z2 & 1);
  const u8 val = (u8) (k[sel] ^ ns.b);

  ns.l = (u8) ((val + s.l + s.r) & 0xFF);
  ns.r = (u8) ((val + s.l)       & 0xFF);

  return ns;
}

DECLSPEC u8 reflect8 (u8 b)
{
  b = (u8) (((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
  b = (u8) (((b & 0xCC) >> 2) | ((b & 0x33) << 2));
  b = (u8) (((b & 0xAA) >> 1) | ((b & 0x55) << 1));
  return b;
}

DECLSPEC u32 iclass_mac (PRIVATE_AS const u8 *rev_ccnr, PRIVATE_AS const u8 *div_key)
{
  iclass_state_t state;
  state.l = (u8) (((div_key[0] ^ 0x4C) + 0xEC) & 0xFF);
  state.r = (u8) (((div_key[0] ^ 0x4C) + 0x21) & 0xFF);
  state.b = 0x4C;
  state.t = 0xE012;

  for (int i = 0; i < 12; i++)
  {
    const u8 rb = rev_ccnr[i];
    for (int bit = 7; bit >= 0; bit--)
    {
      state = iclass_successor (div_key, state, (rb >> bit) & 1);
    }
  }

  u8 mac[4] = { 0, 0, 0, 0 };

  for (int i = 0; i < 4; i++)
  {
    for (int bit = 7; bit >= 0; bit--)
    {
      mac[i] |= (u8) (((state.r >> 2) & 1) << bit);
      state = iclass_successor (div_key, state, 0);
    }
  }

  return ((u32) reflect8 (mac[0]) << 24)
       | ((u32) reflect8 (mac[1]) << 16)
       | ((u32) reflect8 (mac[2]) <<  8)
       | ((u32) reflect8 (mac[3])      );
}

DECLSPEC void unpack_be32 (const u32 w, PRIVATE_AS u8 *out)
{
  out[0] = (u8) (w >> 24);
  out[1] = (u8) (w >> 16);
  out[2] = (u8) (w >>  8);
  out[3] = (u8) (w      );
}

KERNEL_FQ KERNEL_FA void m64000_mxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = 0;
  pw_buf0[3] = 0;
  pw_buf1[0] = 0;
  pw_buf1[1] = 0;
  pw_buf1[2] = 0;
  pw_buf1[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len & 63;

  u8 pk[8];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[0], pk + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[1], pk + 4);

  u8 ccnr1_bytes[12];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[2], ccnr1_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[3], ccnr1_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[4], ccnr1_bytes + 8);

  u8 rev_ccnr1[12];
  for (int i = 0; i < 12; i++) rev_ccnr1[i] = reflect8 (ccnr1_bytes[i]);

  u8 ccnr2_bytes[12];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[5], ccnr2_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[6], ccnr2_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[7], ccnr2_bytes + 8);

  const u32 mac2_target = salt_bufs[SALT_POS_HOST].salt_buf[8];

  u8 rev_ccnr2[12];
  for (int i = 0; i < 12; i++) rev_ccnr2[i] = reflect8 (ccnr2_bytes[i]);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w0[2];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];

    const u64 idx = ((u64) (w0[1] & 0xFF) << 32) | (u64) w0[0];

    u8 div_key[8];

    for (int j = 0; j < 8; j++)
    {
      div_key[j] = (pk[j] & 0x07) | (u8) (((idx >> (35 - 5 * j)) & 0x1F) << 3);
    }

    const u32 computed1 = iclass_mac (rev_ccnr1, div_key);

    for (u32 d = 0; d < DIGESTS_CNT; d++)
    {
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + d;

      if (computed1 != digests_buf[final_hash_pos].digest_buf[DGST_R0]) continue;

      const u32 computed2 = iclass_mac (rev_ccnr2, div_key);

      if (computed2 != mac2_target) continue;

      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, d, final_hash_pos, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m64000_sxx (KERN_ATTR_BASIC ())
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = 0;
  pw_buf0[3] = 0;
  pw_buf1[0] = 0;
  pw_buf1[1] = 0;
  pw_buf1[2] = 0;
  pw_buf1[3] = 0;

  const u32 pw_l_len = pws[gid].pw_len & 63;

  u8 pk[8];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[0], pk + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[1], pk + 4);

  u8 ccnr1_bytes[12];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[2], ccnr1_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[3], ccnr1_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[4], ccnr1_bytes + 8);

  u8 rev_ccnr1[12];
  for (int i = 0; i < 12; i++) rev_ccnr1[i] = reflect8 (ccnr1_bytes[i]);

  u8 ccnr2_bytes[12];
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[5], ccnr2_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[6], ccnr2_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[7], ccnr2_bytes + 8);

  const u32 mac2_target = salt_bufs[SALT_POS_HOST].salt_buf[8];

  u8 rev_ccnr2[12];
  for (int i = 0; i < 12; i++) rev_ccnr2[i] = reflect8 (ccnr2_bytes[i]);

  const u32 mac1_target = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w0[2];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];

    const u64 idx = ((u64) (w0[1] & 0xFF) << 32) | (u64) w0[0];

    u8 div_key[8];

    for (int j = 0; j < 8; j++)
    {
      div_key[j] = (pk[j] & 0x07) | (u8) (((idx >> (35 - 5 * j)) & 0x1F) << 3);
    }

    const u32 computed1 = iclass_mac (rev_ccnr1, div_key);

    if (computed1 != mac1_target) continue;

    const u32 computed2 = iclass_mac (rev_ccnr2, div_key);

    if (computed2 != mac2_target) continue;

    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos, 0, 0);
    }
  }
}
