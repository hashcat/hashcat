/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#endif

CONSTANT_VK u8a c_ftable[256] =
{
  0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4,
  0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
  0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e,
  0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
  0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68,
  0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
  0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19,
  0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
  0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b,
  0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
  0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0,
  0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
  0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69,
  0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
  0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20,
  0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
  0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43,
  0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
  0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa,
  0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
  0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87,
  0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
  0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b,
  0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
  0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0,
  0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
  0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1,
  0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
  0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5,
  0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
  0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3,
  0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
};

DECLSPEC void g (LOCAL_AS u8 *s_ftable, const u32 *key, const int k, const u32 *wx, u32 *out)
{
  const u32 g1 = wx[1];
  const u32 g2 = wx[0];
  const u32 g3 = s_ftable[g2 ^ key[(4 * k + 0) % 10]] ^ g1;
  const u32 g4 = s_ftable[g3 ^ key[(4 * k + 1) % 10]] ^ g2;
  const u32 g5 = s_ftable[g4 ^ key[(4 * k + 2) % 10]] ^ g3;
  const u32 g6 = s_ftable[g5 ^ key[(4 * k + 3) % 10]] ^ g4;

  out[0] = g6;
  out[1] = g5;
}

DECLSPEC u32 skip32 (LOCAL_AS u8 *s_ftable, const u32 KP, const u32 *key)
{
  u32 wl[2];
  u32 wr[2];

  wl[0] = (KP >>  8) & 0xff;
  wl[1] = (KP >>  0) & 0xff;
  wr[0] = (KP >> 24) & 0xff;
  wr[1] = (KP >> 16) & 0xff;

  for (u32 i = 0; i < 12; i++)
  {
    const u32 k0 = (i * 2) + 0;
    const u32 k1 = (i * 2) + 1;

    u32 tmp[2];

    g (s_ftable, key, k0, wl, tmp);

    tmp[0] ^= k0;

    wr[0] ^= tmp[0];
    wr[1] ^= tmp[1];

    g (s_ftable, key, k1, wr, tmp);

    tmp[0] ^= k1;

    wl[0] ^= tmp[0];
    wl[1] ^= tmp[1];
  }

  const u32 r = ((wr[1] & 0xff) <<  0)
              | ((wr[0] & 0xff) <<  8)
              | ((wl[1] & 0xff) << 16)
              | ((wl[0] & 0xff) << 24);

  return r;
}

KERNEL_FQ void m14900_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_ftable
   */

  LOCAL_VK u8 s_ftable[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_ftable[i] = c_ftable[i];
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u32 KP = salt_bufs[salt_pos].salt_buf[0];

  /**
   * main
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32 key[10];

    key[0] = (w0[0] >>  0) & 0xff;
    key[1] = (w0[0] >>  8) & 0xff;
    key[2] = (w0[0] >> 16) & 0xff;
    key[3] = (w0[0] >> 24) & 0xff;
    key[4] = (w0[1] >>  0) & 0xff;
    key[5] = (w0[1] >>  8) & 0xff;
    key[6] = (w0[1] >> 16) & 0xff;
    key[7] = (w0[1] >> 24) & 0xff;
    key[8] = (w0[2] >>  0) & 0xff;
    key[9] = (w0[2] >>  8) & 0xff;

    const u32 r = skip32 (s_ftable, KP, key);

    const u32 z = 0;

    COMPARE_M_SIMD (r, z, z, z);
  }
}

KERNEL_FQ void m14900_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m14900_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m14900_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_ftable
   */

  LOCAL_VK u8 s_ftable[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_ftable[i] = c_ftable[i];
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  const u32 KP = salt_bufs[salt_pos].salt_buf[0];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * main
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32 key[10];

    key[0] = (w0[0] >>  0) & 0xff;
    key[1] = (w0[0] >>  8) & 0xff;
    key[2] = (w0[0] >> 16) & 0xff;
    key[3] = (w0[0] >> 24) & 0xff;
    key[4] = (w0[1] >>  0) & 0xff;
    key[5] = (w0[1] >>  8) & 0xff;
    key[6] = (w0[1] >> 16) & 0xff;
    key[7] = (w0[1] >> 24) & 0xff;
    key[8] = (w0[2] >>  0) & 0xff;
    key[9] = (w0[2] >>  8) & 0xff;

    const u32 r = skip32 (s_ftable, KP, key);

    const u32 z = 0;

    COMPARE_S_SIMD (r, z, z, z);
  }
}

KERNEL_FQ void m14900_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m14900_s16 (KERN_ATTR_RULES ())
{
}
