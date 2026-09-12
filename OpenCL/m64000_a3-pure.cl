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

DECLSPEC u32 bs_mux8 (const u32 z0, const u32 z1, const u32 z2,
                      const u32 nz0, const u32 nz1, const u32 nz2,
                      const u32 v0, const u32 v1, const u32 v2, const u32 v3,
                      const u32 v4, const u32 v5, const u32 v6, const u32 v7)
{
  const u32 a0 = (z2 & v1) | (nz2 & v0);
  const u32 a1 = (z2 & v3) | (nz2 & v2);
  const u32 a2 = (z2 & v5) | (nz2 & v4);
  const u32 a3 = (z2 & v7) | (nz2 & v6);

  const u32 b0 = (z1 & a1) | (nz1 & a0);
  const u32 b1 = (z1 & a3) | (nz1 & a2);

  return (z0 & b1) | (nz0 & b0);
}

DECLSPEC void bs_add8 (PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b, PRIVATE_AS u32 *out)
{
  u32 carry = 0;

  for (int i = 0; i < 8; i++)
  {
    const u32 x = a[i] ^ b[i];

    out[i] = x ^ carry;

    carry = (a[i] & b[i]) | (carry & x);
  }
}

DECLSPEC void bs_iclass_tick (PRIVATE_AS u32 *t, PRIVATE_AS u32 *b,
                              PRIVATE_AS u32 *l, PRIVATE_AS u32 *r,
                              PRIVATE_AS const u32 *kb,
                              const u32 y_bs)
{
  const u32 Tt = t[15] ^ t[14] ^ t[10] ^ t[8] ^ t[5] ^ t[4] ^ t[1] ^ t[0];
  const u32 Bt = b[6] ^ b[5] ^ b[4] ^ b[0];

  const u32 cr0 = r[7], cr1 = r[6], cr2 = r[5], cr3 = r[4];
  const u32 cr4 = r[3], cr5 = r[2], cr6 = r[1], cr7 = r[0];

  const u32 new_t = Tt ^ cr0 ^ cr4;
  const u32 new_b = Bt ^ cr7;

  t[ 0] = t[ 1]; t[ 1] = t[ 2]; t[ 2] = t[ 3]; t[ 3] = t[ 4];
  t[ 4] = t[ 5]; t[ 5] = t[ 6]; t[ 6] = t[ 7]; t[ 7] = t[ 8];
  t[ 8] = t[ 9]; t[ 9] = t[10]; t[10] = t[11]; t[11] = t[12];
  t[12] = t[13]; t[13] = t[14]; t[14] = t[15]; t[15] = new_t;

  b[0] = b[1]; b[1] = b[2]; b[2] = b[3]; b[3] = b[4];
  b[4] = b[5]; b[5] = b[6]; b[6] = b[7]; b[7] = new_b;

  const u32 ncr3 = ~cr3;
  const u32 ncr5 = ~cr5;

  const u32 z0 = (cr0 & cr2) ^ (cr1 & ncr3) ^ (cr2 | cr4);
  const u32 z1 = (cr0 | cr2) ^ (cr5 | cr7) ^ cr1 ^ cr6 ^ Tt ^ y_bs;
  const u32 z2 = (cr3 & ncr5) ^ (cr4 & cr6) ^ cr7 ^ Tt;

  const u32 nz0 = ~z0, nz1 = ~z1, nz2 = ~z2;

  u32 val[8];

  for (int bit = 0; bit < 8; bit++)
  {
    val[bit] = bs_mux8 (z0, z1, z2, nz0, nz1, nz2,
                        kb[0 * 8 + bit], kb[1 * 8 + bit],
                        kb[2 * 8 + bit], kb[3 * 8 + bit],
                        kb[4 * 8 + bit], kb[5 * 8 + bit],
                        kb[6 * 8 + bit], kb[7 * 8 + bit]);
  }

  val[0] ^= b[0]; val[1] ^= b[1]; val[2] ^= b[2]; val[3] ^= b[3];
  val[4] ^= b[4]; val[5] ^= b[5]; val[6] ^= b[6]; val[7] ^= b[7];

  u32 old_r[8];

  for (int bit = 0; bit < 8; bit++)
  {
    old_r[bit] = r[bit];
  }

  bs_add8 (val, l, r);
  bs_add8 (r, old_r, l);
}

KERNEL_FQ KERNEL_FA void m64000_mxx (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  u8 pk[8];

  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[0], pk + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[1], pk + 4);

  u8 ccnr1_bytes[12], ccnr2_bytes[12];

  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[2], ccnr1_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[3], ccnr1_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[4], ccnr1_bytes + 8);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[5], ccnr2_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[6], ccnr2_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[7], ccnr2_bytes + 8);

  const u32 mac2_target = salt_bufs[SALT_POS_HOST].salt_buf[8];

  u8 rev_ccnr2[12];

  for (int i = 0; i < 12; i++)
  {
    rev_ccnr2[i] = reflect8 (ccnr2_bytes[i]);
  }

  u32 y_ccnr[96];

  for (int i = 0; i < 12; i++)
  {
    u8 rb = reflect8 (ccnr1_bytes[i]);

    for (int bit = 7; bit >= 0; bit--)
    {
      y_ccnr[i * 8 + (7 - bit)] = ((rb >> bit) & 1) ? 0xFFFFFFFF : 0;
    }
  }

  u32 kb_const[64];

  for (int j = 0; j < 8; j++)
  {
    kb_const[j * 8 + 0] = (pk[j] & 0x01) ? 0xFFFFFFFF : 0;
    kb_const[j * 8 + 1] = (pk[j] & 0x02) ? 0xFFFFFFFF : 0;
    kb_const[j * 8 + 2] = (pk[j] & 0x04) ? 0xFFFFFFFF : 0;

    for (int bit = 3; bit < 8; bit++)
    {
      kb_const[j * 8 + bit] = 0;
    }
  }

  /**
   * base
   */

  const u32 w0l = pws[gid].i[0];
  const u32 w1  = pws[gid].i[1];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += 32)
  {
    const u32 batch_cnt = ((il_pos + 32) <= IL_CNT) ? 32 : (IL_CNT - il_pos);

    u32 kb[64];

    for (int j = 0; j < 64; j++)
    {
      kb[j] = kb_const[j];
    }

    for (u32 i = 0; i < batch_cnt; i++)
    {
      const u32 w0 = w0l | bfs_buf[il_pos + i].i;
      const u64 idx = ((u64) (w1 & 0xFF) << 32) | (u64) w0;

      for (int j = 0; j < 8; j++)
      {
        const u32 five = (u32) ((idx >> (35 - 5 * j)) & 0x1F);

        kb[j * 8 + 3] |= ((five >> 0) & 1) << i;
        kb[j * 8 + 4] |= ((five >> 1) & 1) << i;
        kb[j * 8 + 5] |= ((five >> 2) & 1) << i;
        kb[j * 8 + 6] |= ((five >> 3) & 1) << i;
        kb[j * 8 + 7] |= ((five >> 4) & 1) << i;
      }
    }

    u32 k0xor[8];

    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = kb[2] ^ 0xFFFFFFFF;
    k0xor[3] = kb[3] ^ 0xFFFFFFFF;
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = kb[6] ^ 0xFFFFFFFF;
    k0xor[7] = kb[7];

    u32 ec[8] = { 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    u32 x21[8] = { 0xFFFFFFFF, 0, 0, 0, 0, 0xFFFFFFFF, 0, 0 };

    u32 l[8], r[8];

    bs_add8 (k0xor, ec, l);
    bs_add8 (k0xor, x21, r);

    u32 t[16] = { 0, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    u32 b[8]  = { 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0 };

    for (int tick = 0; tick < 96; tick++)
    {
      bs_iclass_tick (t, b, l, r, kb, y_ccnr[tick]);
    }

    u32 mac_bp[32];

    for (int tick = 0; tick < 32; tick++)
    {
      mac_bp[tick] = r[2];

      if (tick < 31)
      {
        bs_iclass_tick (t, b, l, r, kb, 0);
      }
    }

    for (u32 i = 0; i < batch_cnt; i++)
    {
      u32 computed1 = 0;

      for (int tick = 0; tick < 32; tick++)
      {
        const u32 bit_val = (mac_bp[tick] >> i) & 1;

        computed1 |= bit_val << ((tick % 8) + (3 - tick / 8) * 8);
      }

      for (u32 d = 0; d < DIGESTS_CNT; d++)
      {
        const u32 final_hash_pos = DIGESTS_OFFSET_HOST + d;

        if (computed1 != digests_buf[final_hash_pos].digest_buf[DGST_R0]) continue;

        const u32 w0 = w0l | bfs_buf[il_pos + i].i;
        const u64 idx = ((u64) (w1 & 0xFF) << 32) | (u64) w0;

        u8 div_key[8];

        for (int j = 0; j < 8; j++)
        {
          div_key[j] = (pk[j] & 0x07) | (u8) (((idx >> (35 - 5 * j)) & 0x1F) << 3);
        }

        const u32 computed2 = iclass_mac (rev_ccnr2, div_key);

        if (computed2 != mac2_target) continue;

        if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, d, final_hash_pos, gid, il_pos + i, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m64000_sxx (KERN_ATTR_BASIC ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  u8 pk[8];

  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[0], pk + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[1], pk + 4);

  u8 ccnr1_bytes[12], ccnr2_bytes[12];

  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[2], ccnr1_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[3], ccnr1_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[4], ccnr1_bytes + 8);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[5], ccnr2_bytes + 0);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[6], ccnr2_bytes + 4);
  unpack_be32 (salt_bufs[SALT_POS_HOST].salt_buf[7], ccnr2_bytes + 8);

  const u32 mac2_target = salt_bufs[SALT_POS_HOST].salt_buf[8];

  u8 rev_ccnr2[12];

  for (int i = 0; i < 12; i++)
  {
    rev_ccnr2[i] = reflect8 (ccnr2_bytes[i]);
  }

  u32 y_ccnr[96];

  for (int i = 0; i < 12; i++)
  {
    u8 rb = reflect8 (ccnr1_bytes[i]);

    for (int bit = 7; bit >= 0; bit--)
    {
      y_ccnr[i * 8 + (7 - bit)] = ((rb >> bit) & 1) ? 0xFFFFFFFF : 0;
    }
  }

  u32 kb_const[64];

  for (int j = 0; j < 8; j++)
  {
    kb_const[j * 8 + 0] = (pk[j] & 0x01) ? 0xFFFFFFFF : 0;
    kb_const[j * 8 + 1] = (pk[j] & 0x02) ? 0xFFFFFFFF : 0;
    kb_const[j * 8 + 2] = (pk[j] & 0x04) ? 0xFFFFFFFF : 0;

    for (int bit = 3; bit < 8; bit++)
    {
      kb_const[j * 8 + bit] = 0;
    }
  }

  const u32 mac1_target = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];

  u32 mac1_bs[32];

  for (int i = 0; i < 4; i++)
  {
    const u8 target_byte = (u8) (mac1_target >> (24 - i * 8));

    for (int bit = 0; bit < 8; bit++)
    {
      mac1_bs[i * 8 + bit] = ((target_byte >> bit) & 1) ? 0xFFFFFFFF : 0;
    }
  }

  /**
   * base
   */

  const u32 w0l = pws[gid].i[0];
  const u32 w1  = pws[gid].i[1];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += 32)
  {
    const u32 batch_cnt = ((il_pos + 32) <= IL_CNT) ? 32 : (IL_CNT - il_pos);

    u32 kb[64];

    for (int j = 0; j < 64; j++)
    {
      kb[j] = kb_const[j];
    }

    for (u32 i = 0; i < batch_cnt; i++)
    {
      const u32 w0 = w0l | bfs_buf[il_pos + i].i;
      const u64 idx = ((u64) (w1 & 0xFF) << 32) | (u64) w0;

      for (int j = 0; j < 8; j++)
      {
        const u32 five = (u32) ((idx >> (35 - 5 * j)) & 0x1F);

        kb[j * 8 + 3] |= ((five >> 0) & 1) << i;
        kb[j * 8 + 4] |= ((five >> 1) & 1) << i;
        kb[j * 8 + 5] |= ((five >> 2) & 1) << i;
        kb[j * 8 + 6] |= ((five >> 3) & 1) << i;
        kb[j * 8 + 7] |= ((five >> 4) & 1) << i;
      }
    }

    u32 k0xor[8];

    k0xor[0] = kb[0];
    k0xor[1] = kb[1];
    k0xor[2] = kb[2] ^ 0xFFFFFFFF;
    k0xor[3] = kb[3] ^ 0xFFFFFFFF;
    k0xor[4] = kb[4];
    k0xor[5] = kb[5];
    k0xor[6] = kb[6] ^ 0xFFFFFFFF;
    k0xor[7] = kb[7];

    u32 ec[8] = { 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    u32 x21[8] = { 0xFFFFFFFF, 0, 0, 0, 0, 0xFFFFFFFF, 0, 0 };

    u32 l[8], r[8];

    bs_add8 (k0xor, ec, l);
    bs_add8 (k0xor, x21, r);

    u32 t[16] = { 0, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    u32 b[8]  = { 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0 };

    for (int tick = 0; tick < 96; tick++)
    {
      bs_iclass_tick (t, b, l, r, kb, y_ccnr[tick]);
    }

    u32 mac_match = 0xFFFFFFFF;

    if (batch_cnt < 32)
    {
      mac_match &= (1u << batch_cnt) - 1;
    }

    for (int tick = 0; tick < 32; tick++)
    {
      const u32 target = mac1_bs[(tick / 8) * 8 + (tick % 8)];

      mac_match &= ~(r[2] ^ target);

      if (tick == 7 && mac_match == 0) break;
      if (tick == 15 && mac_match == 0) break;

      bs_iclass_tick (t, b, l, r, kb, 0);
    }

    if (mac_match == 0) continue;

    for (u32 i = 0; i < batch_cnt; i++)
    {
      if (((mac_match >> i) & 1) == 0) continue;

      const u32 w0 = w0l | bfs_buf[il_pos + i].i;
      const u64 idx = ((u64) (w1 & 0xFF) << 32) | (u64) w0;

      u8 div_key[8];

      for (int j = 0; j < 8; j++)
      {
        div_key[j] = (pk[j] & 0x07) | (u8) (((idx >> (35 - 5 * j)) & 0x1F) << 3);
      }

      const u32 computed2 = iclass_mac (rev_ccnr2, div_key);

      if (computed2 != mac2_target) continue;

      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;

      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, gid, il_pos + i, 0, 0);
      }
    }
  }
}
