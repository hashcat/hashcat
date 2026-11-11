/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#endif

typedef struct bfe
{
  u32 endian;
  u32 comp;

  u32 ct[4];

} bfe_t;

DECLSPEC u32 bfe_byte (PRIVATE_AS const u32 *w, const u32 j)
{
  return (w[j >> 2] >> ((j & 3) * 8)) & 0xff;
}

DECLSPEC void bfe_init_key (PRIVATE_AS const u32 *kb, const u32 kb_len, PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  // the classic Blowfish key schedule: P[i] ^= 4 key bytes big-endian, cycling the key

  u32 E[18];

  for (int i = 0; i < 18; i++)
  {
    u32 v = 0;

    for (int k = 0; k < 4; k++)
    {
      const u32 j = ((u32) (i * 4 + k)) % kb_len;

      v = (v << 8) | bfe_byte (kb, j);
    }

    E[i] = v;
  }

  blowfish_set_key (E, 18, P, S0, S1, S2, S3);
}

DECLSPEC bool bfe_check (PRIVATE_AS const u32 *w, const u32 pw_len, const u32 endian, PRIVATE_AS const u32 *ct, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  // key schedule on the passphrase

  u32 P[18];

  bfe_init_key (w, pw_len, P, S0, S1, S2, S3);

  // mutateKey: chain-encrypt the first 8 passphrase bytes into the 56 byte data key

  u32 L = w[0];
  u32 R = w[1];

  if (endian == 1)
  {
    L = hc_swap32_S (L);
    R = hc_swap32_S (R);
  }

  u32 mk[14];

  for (int i = 0; i < 14; i += 2)
  {
    BF_ENCRYPT (L, R);

    mk[i + 0] = L;
    mk[i + 1] = R;
  }

  if (endian == 1)
  {
    for (int i = 0; i < 14; i++)
    {
      mk[i] = hc_swap32_S (mk[i]);
    }
  }

  // key schedule on the data key

  bfe_init_key (mk, 56, P, S0, S1, S2, S3);

  // the last two blocks hold the key tail, minus up to 7 bytes of zero padding

  u32 pt[4];

  pt[0] = ct[0];
  pt[1] = ct[1];
  pt[2] = ct[2];
  pt[3] = ct[3];

  if (endian == 1)
  {
    pt[0] = hc_swap32_S (pt[0]);
    pt[1] = hc_swap32_S (pt[1]);
    pt[2] = hc_swap32_S (pt[2]);
    pt[3] = hc_swap32_S (pt[3]);
  }

  BF_DECRYPT (pt[0], pt[1]);
  BF_DECRYPT (pt[2], pt[3]);

  if (endian == 1)
  {
    pt[0] = hc_swap32_S (pt[0]);
    pt[1] = hc_swap32_S (pt[1]);
    pt[2] = hc_swap32_S (pt[2]);
    pt[3] = hc_swap32_S (pt[3]);
  }

  for (u32 pad = 0; pad < 8; pad++)
  {
    bool ok = true;

    for (u32 j = 0; j < 16 - pad; j++)
    {
      if (bfe_byte (pt, j) != bfe_byte (mk, 40 + pad + j))
      {
        ok = false;

        break;
      }
    }

    if (ok == false) continue;

    for (u32 j = 16 - pad; j < 16; j++)
    {
      if (bfe_byte (pt, j) != 0)
      {
        ok = false;

        break;
      }
    }

    if (ok == true) return true;
  }

  return false;
}

KERNEL_FQ KERNEL_FA void m44800_mxx (KERN_ATTR_RULES_ESALT (bfe_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * blowfish shared
   */

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 endian = esalt_bufs[DIGESTS_OFFSET_HOST].endian;

  u32 ct[4];

  ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0];
  ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1];
  ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[2];
  ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[3];

  // do not COPY_PW() here: its static s_pws[64] takes 16k of shared memory the
  // dynamic S box allocation is sized without, so the S boxes overflow it (CUDA)

  const u32 pw_len0 = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len0; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 tmp[64];

    for (u32 i = 0; i < 64; i++)
    {
      tmp[i] = w[i];
    }

    const u32 tmp_len = apply_rules (rules_buf[il_pos].cmds, tmp, pw_len0);

    if (tmp_len == 0) continue;

    const u32 pw_len = (tmp_len > 56) ? 56 : tmp_len; // the tool silently truncates to 56

    const bool ok = bfe_check (tmp, pw_len, endian, ct, S0, S1, S2, S3);

    if (ok == false) continue;

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ KERNEL_FA void m44800_sxx (KERN_ATTR_RULES_ESALT (bfe_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * blowfish shared
   */

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 endian = esalt_bufs[DIGESTS_OFFSET_HOST].endian;

  u32 ct[4];

  ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0];
  ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1];
  ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[2];
  ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[3];

  // do not COPY_PW() here: its static s_pws[64] takes 16k of shared memory the
  // dynamic S box allocation is sized without, so the S boxes overflow it (CUDA)

  const u32 pw_len0 = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len0; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 tmp[64];

    for (u32 i = 0; i < 64; i++)
    {
      tmp[i] = w[i];
    }

    const u32 tmp_len = apply_rules (rules_buf[il_pos].cmds, tmp, pw_len0);

    if (tmp_len == 0) continue;

    const u32 pw_len = (tmp_len > 56) ? 56 : tmp_len; // the tool silently truncates to 56

    const bool ok = bfe_check (tmp, pw_len, endian, ct, S0, S1, S2, S3);

    if (ok == false) continue;

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}
