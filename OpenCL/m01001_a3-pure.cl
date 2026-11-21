/**
 * Double NTLM - NTLM(NTLM(password)) - Hash Shucking
 * Attack mode 3: Brute-force / Mask
 * License: MIT
 *
 * No NEW_SIMD_CODE: forces VECT_SIZE=1 so double-hash stays scalar.
 * Performance cost is negligible — MD4 is compute-trivial.
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

DECLSPEC u32 nib_to_hex (const u32 n)
{
  return (n < 10) ? (n + 0x30) : (n + 0x57);
}

DECLSPEC void u32_to_hex_utf16le (const u32 val, PRIVATE_AS u32 *out)
{
  const u32 b0 = (val >>  0) & 0xff;
  const u32 b1 = (val >>  8) & 0xff;
  const u32 b2 = (val >> 16) & 0xff;
  const u32 b3 = (val >> 24) & 0xff;

  out[0] = nib_to_hex (b0 >> 4) | (nib_to_hex (b0 & 0xf) << 16);
  out[1] = nib_to_hex (b1 >> 4) | (nib_to_hex (b1 & 0xf) << 16);
  out[2] = nib_to_hex (b2 >> 4) | (nib_to_hex (b2 & 0xf) << 16);
  out[3] = nib_to_hex (b3 >> 4) | (nib_to_hex (b3 & 0xf) << 16);
}

KERNEL_FQ KERNEL_FA void m01001_mxx (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, w, pw_len);

    md4_final (&ctx1);

    u32 hex_buf[16];

    u32_to_hex_utf16le (ctx1.h[0], hex_buf +  0);
    u32_to_hex_utf16le (ctx1.h[1], hex_buf +  4);
    u32_to_hex_utf16le (ctx1.h[2], hex_buf +  8);
    u32_to_hex_utf16le (ctx1.h[3], hex_buf + 12);

    md4_ctx_t ctx2;

    md4_init (&ctx2);

    md4_update (&ctx2, hex_buf, 64);

    md4_final (&ctx2);

    const u32x r0 = ctx2.h[DGST_R0];
    const u32x r1 = ctx2.h[DGST_R1];
    const u32x r2 = ctx2.h[DGST_R2];
    const u32x r3 = ctx2.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m01001_sxx (KERN_ATTR_VECTOR ())
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, w, pw_len);

    md4_final (&ctx1);

    u32 hex_buf[16];

    u32_to_hex_utf16le (ctx1.h[0], hex_buf +  0);
    u32_to_hex_utf16le (ctx1.h[1], hex_buf +  4);
    u32_to_hex_utf16le (ctx1.h[2], hex_buf +  8);
    u32_to_hex_utf16le (ctx1.h[3], hex_buf + 12);

    md4_ctx_t ctx2;

    md4_init (&ctx2);

    md4_update (&ctx2, hex_buf, 64);

    md4_final (&ctx2);

    const u32x r0 = ctx2.h[DGST_R0];
    const u32x r1 = ctx2.h[DGST_R1];
    const u32x r2 = ctx2.h[DGST_R2];
    const u32x r3 = ctx2.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
