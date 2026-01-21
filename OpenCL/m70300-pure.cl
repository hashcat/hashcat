/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * bcrypt $2*$, Blowfish (Unix) - LiteX FPGA Accelerated
 *
 * This kernel is minimal as the LiteX-Bcrypt FPGA bridge handles
 * the actual bcrypt computation. The _init kernel copies passwords
 * to the tmp structure, _loop is empty (bridge handles it), and
 * _comp checks if the bridge marked the hash as cracked.
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

/**
 * FPGA tmp structure - must match module_70300.c and bridge_litex_bcrypt.c
 */

typedef struct bcrypt_fpga_tmp
{
  u32 pw_buf[18];   // Password buffer (up to 72 bytes for bcrypt)
  u32 pw_len;
  u32 digest[6];    // Output from FPGA (24 bytes, 6 words)
  u32 cracked;      // Flag set by bridge when FPGA reports match

} bcrypt_fpga_tmp_t;

/**
 * _init kernel: Copy password from pws[] to tmps[]
 *
 * This prepares the password data for the bridge to send to the FPGA.
 */

KERNEL_FQ KERNEL_FA void m70300_init (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  // Copy password buffer (up to 72 bytes = 18 u32s)
  for (u32 i = 0; i < 18; i++)
  {
    tmps[gid].pw_buf[i] = pws[gid].i[i];
  }

  tmps[gid].pw_len = pw_len;
  tmps[gid].cracked = 0;

  // Clear digest
  for (u32 i = 0; i < 6; i++)
  {
    tmps[gid].digest[i] = 0;
  }
}

/**
 * _loop kernel: Empty - bridge handles FPGA computation
 *
 * The LiteX-Bcrypt bridge sends passwords to the FPGA and receives
 * results. This kernel is not used but must exist for hashcat.
 */

KERNEL_FQ KERNEL_FA void m70300_loop (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  // Empty - bridge replaces this kernel
}

/**
 * _comp kernel: Check if bridge marked this candidate as cracked
 *
 * The bridge sets tmps[gid].cracked = 1 when the FPGA reports a match.
 * We check this flag and mark the hash as cracked if set.
 */

KERNEL_FQ KERNEL_FA void m70300_comp (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // Check if the bridge marked this as cracked
  // The FPGA compares internally and tells us which password matched
  // We use the target digest values directly since FPGA already confirmed the match
  if (tmps[gid].cracked == 1)
  {
    // Use the target digest values - FPGA already confirmed this is the match
    const u32 r0 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];
    const u32 r1 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1];
    const u32 r2 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2];
    const u32 r3 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3];

    #define il_pos 0

    #ifdef KERNEL_STATIC
    #include COMPARE_M
    #endif
  }
}
