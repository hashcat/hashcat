/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_shared.h)
#endif

DECLSPEC void gpu_decompress_entry (GLOBAL_AS pw_idx_t *pws_idx, GLOBAL_AS u32 *pws_comp, PRIVATE_AS pw_t *buf, const u64 gid)
{
  const u32 off = pws_idx[gid].off;
  const u32 cnt = pws_idx[gid].cnt;
  const u32 len = pws_idx[gid].len;

  pw_t pw;

  pw.i[ 0] = 0;
  pw.i[ 1] = 0;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0;

  pw.pw_len = len;

  for (u32 i = 0, j = off; i < cnt; i++, j++)
  {
    pw.i[i] = pws_comp[j];
  }

  *buf = pw;
}

KERNEL_FQ void gpu_decompress (KERN_ATTR_GPU_DECOMPRESS)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw;

  gpu_decompress_entry (pws_idx, pws_comp, &pw, gid);

  pws_buf[gid] = pw;
}

KERNEL_FQ void gpu_memset (KERN_ATTR_GPU_MEMSET)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  uint4 r;

  #if   defined IS_NATIVE
  r = value;
  #elif defined IS_OPENCL
  r = (uint4) (value);
  #elif defined IS_CUDA
  r.x = value;
  r.y = value;
  r.z = value;
  r.w = value;
  #elif defined IS_HIP
  r.x = value;
  r.y = value;
  r.z = value;
  r.w = value;
  #elif defined IS_METAL
  r.x = value;
  r.y = value;
  r.z = value;
  r.w = value;
  #endif

  buf[gid] = r;
}

KERNEL_FQ void gpu_bzero (KERN_ATTR_GPU_BZERO)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  uint4 r;

  #if   defined IS_NATIVE
  r = 0;
  #elif defined IS_OPENCL
  r = (uint4) (0);
  #elif defined IS_CUDA
  r.x = 0;
  r.y = 0;
  r.z = 0;
  r.w = 0;
  #elif defined IS_HIP
  r.x = 0;
  r.y = 0;
  r.z = 0;
  r.w = 0;
  #elif defined IS_METAL
  r.x = 0;
  r.y = 0;
  r.z = 0;
  r.w = 0;
  #endif

  buf[gid] = r;
}

KERNEL_FQ void gpu_atinit (KERN_ATTR_GPU_ATINIT)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 l32 = l32_from_64_S (gid);
  const u32 h32 = h32_from_64_S (gid);

  pw_t pw;

  pw.i[ 0] = 0x5c5c5c5c ^ l32;
  pw.i[ 1] = 0x36363636 ^ h32;
  pw.i[ 2] = 0;
  pw.i[ 3] = 0;
  pw.i[ 4] = 0;
  pw.i[ 5] = 0;
  pw.i[ 6] = 0;
  pw.i[ 7] = 0;
  pw.i[ 8] = 0;
  pw.i[ 9] = 0;
  pw.i[10] = 0;
  pw.i[11] = 0;
  pw.i[12] = 0;
  pw.i[13] = 0;
  pw.i[14] = 0;
  pw.i[15] = 0;
  pw.i[16] = 0;
  pw.i[17] = 0;
  pw.i[18] = 0;
  pw.i[19] = 0;
  pw.i[20] = 0;
  pw.i[21] = 0;
  pw.i[22] = 0;
  pw.i[23] = 0;
  pw.i[24] = 0;
  pw.i[25] = 0;
  pw.i[26] = 0;
  pw.i[27] = 0;
  pw.i[28] = 0;
  pw.i[29] = 0;
  pw.i[30] = 0;
  pw.i[31] = 0;
  pw.i[32] = 0;
  pw.i[33] = 0;
  pw.i[34] = 0;
  pw.i[35] = 0;
  pw.i[36] = 0;
  pw.i[37] = 0;
  pw.i[38] = 0;
  pw.i[39] = 0;
  pw.i[40] = 0;
  pw.i[41] = 0;
  pw.i[42] = 0;
  pw.i[43] = 0;
  pw.i[44] = 0;
  pw.i[45] = 0;
  pw.i[46] = 0;
  pw.i[47] = 0;
  pw.i[48] = 0;
  pw.i[49] = 0;
  pw.i[50] = 0;
  pw.i[51] = 0;
  pw.i[52] = 0;
  pw.i[53] = 0;
  pw.i[54] = 0;
  pw.i[55] = 0;
  pw.i[56] = 0;
  pw.i[57] = 0;
  pw.i[58] = 0;
  pw.i[59] = 0;
  pw.i[60] = 0;
  pw.i[61] = 0;
  pw.i[62] = 0;
  pw.i[63] = 0; // yep that's faster

  //pw.pw_len = 1 + (l32 & 15);
  pw.pw_len = 7; // some algorithms are very sensible on this (example: 12500)

  buf[gid] = pw;
}

KERNEL_FQ void gpu_utf8_to_utf16 (KERN_ATTR_GPU_UTF8_TO_UTF16)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  pw_t pw_in = pws_buf[gid];

  pw_t pw_out;

  for (int i = 0; i < 64; i++) pw_out.i[i] = 0;

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  // note that this can result in pw_len = -1
  // need to check for pw_len in kernel

  pw_out.pw_len = hc_enc_next (&hc_enc, pw_in.i, pw_in.pw_len, 256, pw_out.i, 256);

  pws_buf[gid] = pw_out;
}
