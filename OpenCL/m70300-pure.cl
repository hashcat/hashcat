/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * bcrypt $2*$, Blowfish (Unix) - LiteX FPGA Accelerated
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bcrypt_fpga_tmp
{
  u32 pw_buf[18];   // Password buffer (up to 72 bytes)
  u32 pw_len;
  u32 cracked;      // Flag set by bridge when FPGA reports match

} bcrypt_fpga_tmp_t;

KERNEL_FQ KERNEL_FA void m70300_init (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  for (u32 i = 0; i < 18; i++)
  {
    tmps[gid].pw_buf[i] = pws[gid].i[i];
  }

  tmps[gid].pw_len = pw_len;
  tmps[gid].cracked = 0;
}

KERNEL_FQ KERNEL_FA void m70300_loop (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  // Empty - bridge replaces this kernel
}

KERNEL_FQ KERNEL_FA void m70300_comp (KERN_ATTR_TMPS (bcrypt_fpga_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  if (tmps[gid].cracked == 1)
  {
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
