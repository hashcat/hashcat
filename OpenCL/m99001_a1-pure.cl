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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define MESHTASTIC_NAME_MAX 64
#define MESHTASTIC_CT_MAX   256

typedef struct meshtastic
{
  u32 chash;
  u32 name_xor;
  u32 packet_id;
  u32 from_node;
  u32 name_len;
  u32 ct_len;
  u32 name_buf[MESHTASTIC_NAME_MAX / 4];
  u32 ct_buf[MESHTASTIC_CT_MAX / 4];

} meshtastic_t;

DECLSPEC int meshtastic_chash_match (const u32 psk_xor, const u32 name_xor, const u32 chash, const u32 name_known)
{
  if (name_known)
  {
    return ((psk_xor ^ name_xor) & 0xff) == (chash & 0xff);
  }

  const u32 target = (psk_xor ^ chash) & 0xff;

  return target == 0x0a   /* LongFast   */
      || target == 0x0d   /* LongSlow   */
      || target == 0x6c   /* LongMod    */
      || target == 0x74   /* LongTurbo  */
      || target == 0x1d   /* MediumFast */
      || target == 0x1a   /* MediumSlow */
      || target == 0x72   /* ShortFast  */
      || target == 0x75   /* ShortSlow  */
      || target == 0x0c   /* ShortTurbo */
      || target == 0x4b   /* Default    */
      || target == 0x4c   /* Primary    */
      || target == 0x21   /* Public     */
      || target == 0x6f;  /* admin      */
}

DECLSPEC int meshtastic_verify
(
  PRIVATE_AS const u32 *key_le,
  const u32 chash,
  const u32 name_xor,
  const u32 name_len,
  const u32 packet_id,
  const u32 from_node,
  const u32 ct_len,
  GLOBAL_AS const u32 *ct,
  SHM_TYPE u32 *s_te0,
  SHM_TYPE u32 *s_te1,
  SHM_TYPE u32 *s_te2,
  SHM_TYPE u32 *s_te3,
  SHM_TYPE u32 *s_te4
)
{
  const u32 xw = key_le[0] ^ key_le[1] ^ key_le[2] ^ key_le[3];
  const u32 xh = (xw >> 16) ^ xw;
  const u32 xq = (xh >>  8) ^ xh;

  if (meshtastic_chash_match (xq, name_xor, chash, name_len) == 0) return 0;

  #define MESHTASTIC_KEYLEN 44

  u32 ks[MESHTASTIC_KEYLEN];

  aes128_set_encrypt_key (ks, key_le, s_te0, s_te1, s_te2, s_te3);

  u32 nonce[4];

  nonce[0] = packet_id;
  nonce[1] = 0;
  nonce[2] = from_node;
  nonce[3] = 0;

  u32 ks_block[4];

  aes128_encrypt (ks, nonce, ks_block, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 pt0 = ks_block[0] ^ ct[0];
  const u32 pt1 = ks_block[1] ^ ct[1];
  const u32 pt2 = ks_block[2] ^ ct[2];
  const u32 pt3 = ks_block[3] ^ ct[3];

  const u32 pb_b0 =  pt0        & 0xff;
  const u32 pb_b1 = (pt0 >>  8) & 0xff;
  const u32 pb_b2 = (pt0 >> 16) & 0xff;
  const u32 pb_b3 = (pt0 >> 24) & 0xff;

  if (pb_b0 != 0x08)               return 0;
  if (pb_b1 == 0 || pb_b1 >= 0x80) return 0;
  if (pb_b2 != 0x12)               return 0;
  if (pb_b3 == 0)                  return 0;
  if (pb_b3 + 4 > ct_len)          return 0;

  const u32 trail_pos = 4 + pb_b3;

  if (trail_pos < 16 && trail_pos < ct_len)
  {
    const u32 trail_word = (trail_pos < 4)  ? pt0 :
                           (trail_pos < 8)  ? pt1 :
                           (trail_pos < 12) ? pt2 : pt3;

    const u32 trail_byte = (trail_word >> ((trail_pos & 3) * 8)) & 0xff;

    if (trail_byte != 0x00 &&
        trail_byte != 0x18 &&
        trail_byte != 0x20 &&
        trail_byte != 0x28 &&
        trail_byte != 0x30 &&
        trail_byte != 0x38 &&
        trail_byte != 0x40 &&
        trail_byte != 0x48 &&
        trail_byte != 0x50 &&
        trail_byte != 0x52)
    {
      return 0;
    }
  }

  return 1;
}

KERNEL_FQ KERNEL_FA void m99001_mxx (KERN_ATTR_ESALT (meshtastic_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 base_len = pws[gid].pw_len;

  u32 base[4];

  base[0] = pws[gid].i[0];
  base[1] = pws[gid].i[1];
  base[2] = pws[gid].i[2];
  base[3] = pws[gid].i[3];

  const u32 chash     = esalt_bufs[DIGESTS_OFFSET_HOST].chash;
  const u32 name_xor  = esalt_bufs[DIGESTS_OFFSET_HOST].name_xor;
  const u32 name_len  = esalt_bufs[DIGESTS_OFFSET_HOST].name_len;
  const u32 packet_id = esalt_bufs[DIGESTS_OFFSET_HOST].packet_id;
  const u32 from_node = esalt_bufs[DIGESTS_OFFSET_HOST].from_node;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;
    const u32 total    = base_len + comb_len;
    const u32 plen     = (total < 16) ? total : 16;

    u32 key_le[4];

    key_le[0] = base[0];
    key_le[1] = base[1];
    key_le[2] = base[2];
    key_le[3] = base[3];

    if (base_len < 16)
    {
      // clear bytes >= base_len so we can OR the comb in cleanly
      truncate_block_4x4_le_S (key_le, base_len);

      // shift the first 16 bytes of comb right by base_len in the byte stream
      u32 c0[4] = { 0 };
      u32 c1[4] = { 0 };
      u32 c2[4] = { 0 };
      u32 c3[4] = { 0 };

      c0[0] = combs_buf[il_pos].i[0];
      c0[1] = combs_buf[il_pos].i[1];
      c0[2] = combs_buf[il_pos].i[2];
      c0[3] = combs_buf[il_pos].i[3];

      switch_buffer_by_offset_le_S (c0, c1, c2, c3, base_len);

      key_le[0] |= c0[0];
      key_le[1] |= c0[1];
      key_le[2] |= c0[2];
      key_le[3] |= c0[3];
    }

    truncate_block_4x4_le_S (key_le, plen);

    if (meshtastic_verify (key_le, chash, name_xor, name_len, packet_id, from_node,
                           esalt_bufs[DIGESTS_OFFSET_HOST].ct_len,
                           esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf,
                           s_te0, s_te1, s_te2, s_te3, s_te4) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m99001_sxx (KERN_ATTR_ESALT (meshtastic_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 base_len = pws[gid].pw_len;

  u32 base[4];

  base[0] = pws[gid].i[0];
  base[1] = pws[gid].i[1];
  base[2] = pws[gid].i[2];
  base[3] = pws[gid].i[3];

  const u32 chash     = esalt_bufs[DIGESTS_OFFSET_HOST].chash;
  const u32 name_xor  = esalt_bufs[DIGESTS_OFFSET_HOST].name_xor;
  const u32 name_len  = esalt_bufs[DIGESTS_OFFSET_HOST].name_len;
  const u32 packet_id = esalt_bufs[DIGESTS_OFFSET_HOST].packet_id;
  const u32 from_node = esalt_bufs[DIGESTS_OFFSET_HOST].from_node;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;
    const u32 total    = base_len + comb_len;
    const u32 plen     = (total < 16) ? total : 16;

    u32 key_le[4];

    key_le[0] = base[0];
    key_le[1] = base[1];
    key_le[2] = base[2];
    key_le[3] = base[3];

    if (base_len < 16)
    {
      truncate_block_4x4_le_S (key_le, base_len);

      u32 c0[4] = { 0 };
      u32 c1[4] = { 0 };
      u32 c2[4] = { 0 };
      u32 c3[4] = { 0 };

      c0[0] = combs_buf[il_pos].i[0];
      c0[1] = combs_buf[il_pos].i[1];
      c0[2] = combs_buf[il_pos].i[2];
      c0[3] = combs_buf[il_pos].i[3];

      switch_buffer_by_offset_le_S (c0, c1, c2, c3, base_len);

      key_le[0] |= c0[0];
      key_le[1] |= c0[1];
      key_le[2] |= c0[2];
      key_le[3] |= c0[3];
    }

    truncate_block_4x4_le_S (key_le, plen);

    if (meshtastic_verify (key_le, chash, name_xor, name_len, packet_id, from_node,
                           esalt_bufs[DIGESTS_OFFSET_HOST].ct_len,
                           esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf,
                           s_te0, s_te1, s_te2, s_te3, s_te4) == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
