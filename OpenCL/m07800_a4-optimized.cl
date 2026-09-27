/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

CONSTANT_VK u32a theMagicArray[64] =
{
  0x91ac5114, 0x9f675443, 0x24e73be0, 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f,
  0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194,
  0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3,
  0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3,
  0xb3dd8e0a, 0x24bf51c3, 0x7ccd559f, 0x37af944c, 0x29085282, 0xb23b4e37, 0x9f170791, 0x113bfdcd,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

DECLSPEC u32 GETSHIFTEDINT_CONST (CONSTANT_AS u32a *a, const int n)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (a[d + 0], a[d + 1]);

  tmp <<= m * 8;

  return h32_from_64_S (tmp);
}

DECLSPEC void SETSHIFTEDINT (PRIVATE_AS u32 *a, const int n, const u32 v)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (v, 0);

  tmp >>= m * 8;

  a[d + 0] |= h32_from_64_S (tmp);
  a[d + 1]  = l32_from_64_S (tmp);
}

typedef struct pcfg_hash_ctx
{
  u32 salt_len;
  u32 s[16];

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->salt_len = salt_bufs[salt_pos].salt_len;

  for (u32 i = 0; i < 16; i++) hc->s[i] = salt_bufs[salt_pos].salt_buf[i];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_sap (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *c, const u32 len, PRIVATE_AS u32 *dgst)
{
  const u32 salt_len = hc->salt_len;

  u32 t[16];

  for (u32 i = 0; i < 16; i++) t[i] = 0;

  for (u32 i = 0; i < 8; i++) t[i] = c[i];

  for (u32 i = 0; i <= salt_len; i++) pcfg_put_byte (t, len + i, pcfg_get_byte (hc->s, i));

  u32 final[64];

  for (u32 i = 0; i < 14; i++) final[i] = hc_swap32_S (t[i]);

  final[14] = 0;
  final[15] = (len + salt_len) * 8;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (final + 0, final + 4, final + 8, final + 12, digest);

  // prepare magic array range

  u32 lengthMagicArray = 0x20;
  u32 offsetMagicArray = 0;

  lengthMagicArray += unpack_v8d_from_v32_S (digest[0]) % 6;
  lengthMagicArray += unpack_v8c_from_v32_S (digest[0]) % 6;
  lengthMagicArray += unpack_v8b_from_v32_S (digest[0]) % 6;
  lengthMagicArray += unpack_v8a_from_v32_S (digest[0]) % 6;
  lengthMagicArray += unpack_v8d_from_v32_S (digest[1]) % 6;
  lengthMagicArray += unpack_v8c_from_v32_S (digest[1]) % 6;
  lengthMagicArray += unpack_v8b_from_v32_S (digest[1]) % 6;
  lengthMagicArray += unpack_v8a_from_v32_S (digest[1]) % 6;
  lengthMagicArray += unpack_v8d_from_v32_S (digest[2]) % 6;
  lengthMagicArray += unpack_v8c_from_v32_S (digest[2]) % 6;
  offsetMagicArray += unpack_v8b_from_v32_S (digest[2]) & 7;
  offsetMagicArray += unpack_v8a_from_v32_S (digest[2]) & 7;
  offsetMagicArray += unpack_v8d_from_v32_S (digest[3]) & 7;
  offsetMagicArray += unpack_v8c_from_v32_S (digest[3]) & 7;
  offsetMagicArray += unpack_v8b_from_v32_S (digest[3]) & 7;
  offsetMagicArray += unpack_v8a_from_v32_S (digest[3]) & 7;
  offsetMagicArray += unpack_v8d_from_v32_S (digest[4]) & 7;
  offsetMagicArray += unpack_v8c_from_v32_S (digest[4]) & 7;
  offsetMagicArray += unpack_v8b_from_v32_S (digest[4]) & 7;
  offsetMagicArray += unpack_v8a_from_v32_S (digest[4]) & 7;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  final[ 0] = hc_swap32_S (c[0]);
  final[ 1] = hc_swap32_S (c[1]);
  final[ 2] = hc_swap32_S (c[2]);
  final[ 3] = hc_swap32_S (c[3]);
  final[ 4] = hc_swap32_S (c[4]);
  final[ 5] = hc_swap32_S (c[5]);
  final[ 6] = hc_swap32_S (c[6]);
  final[ 7] = hc_swap32_S (c[7]);
  final[ 8] = 0;
  final[ 9] = 0;
  final[10] = 0;
  final[11] = 0;
  final[12] = 0;
  final[13] = 0;
  final[14] = 0;
  final[15] = 0;

  for (u32 j = 16; j < 64; j++) final[j] = 0;

  u32 final_len = len;

  u32 i;

  // append MagicArray

  for (i = 0; i < lengthMagicArray - 4; i += 4)
  {
    const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i);

    SETSHIFTEDINT (final, final_len + i, tmp);
  }

  const u32 mask = 0xffffffff << (((4 - (lengthMagicArray - i)) & 3) * 8);

  const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i) & mask;

  SETSHIFTEDINT (final, final_len + i, tmp);

  final_len += lengthMagicArray;

  // append Salt

  for (i = 0; i < salt_len + 1; i += 4) // +1 for the 0x80
  {
    const u32 tmp = hc_swap32_S (hc->s[i / 4]); // attention, int[] not char[]

    SETSHIFTEDINT (final, final_len + i, tmp);
  }

  final_len += salt_len;

  // calculate

  const u32 n_blocks = ((final_len + 8) / 64) + 1;

  final[(n_blocks * 16) - 2] = 0;
  final[(n_blocks * 16) - 1] = final_len * 8;

  for (u32 b = 0; b < n_blocks; b++)
  {
    sha1_transform (final + (b * 16) + 0, final + (b * 16) + 4, final + (b * 16) + 8, final + (b * 16) + 12, digest);
  }

  dgst[0] = digest[3];
  dgst[1] = digest[4];
  dgst[2] = digest[2];
  dgst[3] = digest[1];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  if ((len + hc->salt_len) > 55) return false;

  return pcfg_sap (hc, w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 32) return false;

  if ((len + hc->salt_len) > 55) return false;

  u32 c[8];

  for (u32 i = 0; i < 8; i++) c[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_sap (hc, c, len, dgst);
}

#define PCFG_KERNEL_MXX m07800_mxx
#define PCFG_KERNEL_SXX m07800_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
