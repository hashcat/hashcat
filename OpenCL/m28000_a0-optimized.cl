/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible because of branches
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#endif

typedef struct crc64
{
  u64 iv;

} crc64_t;

KERNEL_FQ KERNEL_FA void m28000_m04 (KERN_ATTR_RULES_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * Base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    const u32 out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * crc32c
     */

    u32 w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u64 a = crc64j_opti (w, out_len, iv, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m28000_m08 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ KERNEL_FA void m28000_m16 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ KERNEL_FA void m28000_s04 (KERN_ATTR_RULES_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * Base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32 w0[4] = { 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    const u32 out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * crc32c
     */

    u32 w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = 0;

    u64 a = crc64j_opti (w, out_len, iv, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m28000_s08 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}

KERNEL_FQ KERNEL_FA void m28000_s16 (KERN_ATTR_RULES_ESALT (crc64_t))
{
}
