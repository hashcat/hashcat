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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

CONSTANT_VK u32a sapb_trans_tbl[256] =
{
  // first value hack for 0 byte as part of an optimization
  0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x3f, 0x40, 0x41, 0x50, 0x43, 0x44, 0x45, 0x4b, 0x47, 0x48, 0x4d, 0x4e, 0x54, 0x51, 0x53, 0x46,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x56, 0x55, 0x5c, 0x49, 0x5d, 0x4a,
  0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x58, 0x5b, 0x59, 0xff, 0x52,
  0x4c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x57, 0x5e, 0x5a, 0x4f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

CONSTANT_VK u32a bcodeArray[48] =
{
  0x14, 0x77, 0xf3, 0xd4, 0xbb, 0x71, 0x23, 0xd0, 0x03, 0xff, 0x47, 0x93, 0x55, 0xaa, 0x66, 0x91,
  0xf2, 0x88, 0x6b, 0x99, 0xbf, 0xcb, 0x32, 0x1a, 0x19, 0xd9, 0xa7, 0x82, 0x22, 0x49, 0xa2, 0x51,
  0xe2, 0xb7, 0x33, 0x71, 0x8b, 0x9f, 0x5d, 0x01, 0x44, 0x70, 0xae, 0x11, 0xef, 0x28, 0xf0, 0x0d
};

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL                \
  LOCAL_VK u32 s_sapb_trans_tbl[256];        \
  LOCAL_VK u32 s_bcode[48];                  \
  for (u32 i = lid; i < 256; i += lsz)       \
  {                                          \
    s_sapb_trans_tbl[i] = sapb_trans_tbl[i]; \
  }                                          \
  for (u32 i = lid; i < 48; i += lsz)        \
  {                                          \
    s_bcode[i] = bcodeArray[i];              \
  }                                          \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc)            \
  (hc)->s_sapb_trans_tbl = s_sapb_trans_tbl; \
  (hc)->s_bcode = s_bcode;
#endif

#define SAPB_SALT_WORDS 3
#define SAPB_SALT_BYTES (SAPB_SALT_WORDS * 4)

typedef struct pcfg_hash_ctx
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_sapb_trans_tbl;
  LOCAL_AS u32 *s_bcode;
  #endif

  u32 salt_len;
  u32 s[SAPB_SALT_WORDS];

} pcfg_hash_ctx_t;

DECLSPEC u32 sapb_trans (const u32 in, SHM_TYPE u32 *s_sapb_trans_tbl)
{
  u32 out = 0;

  out |= (s_sapb_trans_tbl[(in >>  0) & 0xff]) <<  0;
  out |= (s_sapb_trans_tbl[(in >>  8) & 0xff]) <<  8;
  out |= (s_sapb_trans_tbl[(in >> 16) & 0xff]) << 16;
  out |= (s_sapb_trans_tbl[(in >> 24) & 0xff]) << 24;

  return out;
}

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_sapb_trans_tbl = hc->s_sapb_trans_tbl;
  #else
  CONSTANT_AS u32a *s_sapb_trans_tbl = sapb_trans_tbl;
  #endif

  hc->salt_len = salt_bufs[salt_pos].salt_len;

  hc->s[0] = sapb_trans (salt_bufs[salt_pos].salt_buf[0], s_sapb_trans_tbl);
  hc->s[1] = sapb_trans (salt_bufs[salt_pos].salt_buf[1], s_sapb_trans_tbl);
  hc->s[2] = sapb_trans (salt_bufs[salt_pos].salt_buf[2], s_sapb_trans_tbl);
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC u32 walld0rf_magic (PRIVATE_AS const u32 *w0, const u32 pw_len, PRIVATE_AS const u32 *salt_buf0, const u32 salt_len, const u32 a, const u32 b, const u32 c, const u32 d, PRIVATE_AS u32 *t, SHM_TYPE u32 *s_bcode)
{
  for (u32 i = 0; i < 16; i++) t[i] = 0;

  u32 sum20 = ((a >> 24) & 3)
            + ((a >> 16) & 3)
            + ((a >>  8) & 3)
            + ((a >>  0) & 3)
            + ((b >>  8) & 3);

  sum20 |= 0x20;

  const u32 w[2] = { w0[0], w0[1] };

  const u32 s[SAPB_SALT_WORDS] = { salt_buf0[0], salt_buf0[1], salt_buf0[2] };

  u32 saved_key[4] = { a, b, c, d };

  u32 i1 = 0;
  u32 i2 = 0;
  u32 i3 = 0;

  while (i2 < sum20)
  {
    if (i1 < pw_len)
    {
      if (pcfg_get_byte (saved_key, 15 - i1) & 1)
      {
        pcfg_put_byte (t, i2, s_bcode[48 - 1 - i1]);

        i2++;

        if (i2 == sum20) break;
      }

      pcfg_put_byte (t, i2, pcfg_get_byte (w, i1));

      i2++;

      if (i2 == sum20) break;

      i1++;
    }

    if (i3 < salt_len)
    {
      pcfg_put_byte (t, i2, (i3 < SAPB_SALT_BYTES) ? pcfg_get_byte (s, i3) : 0);

      i2++;

      if (i2 == sum20) break;

      i3++;
    }

    pcfg_put_byte (t, i2, s_bcode[i2 - i1 - i3]);

    i2++;
    i2++;
  }

  return sum20;
}

DECLSPEC bool pcfg_sapb (PRIVATE_AS const u32 *w_in, const u32 len, PRIVATE_AS u32 *dgst, PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 *s_sapb_trans_tbl = hc->s_sapb_trans_tbl;
  LOCAL_AS u32 *s_bcode          = hc->s_bcode;
  #else
  CONSTANT_AS u32a *s_sapb_trans_tbl = sapb_trans_tbl;
  CONSTANT_AS u32a *s_bcode          = bcodeArray;
  #endif

  u32 w0[2];

  w0[0] = sapb_trans (w_in[0], s_sapb_trans_tbl);
  w0[1] = sapb_trans (w_in[1], s_sapb_trans_tbl);

  u32 t[16];

  for (u32 i = 0; i < 16; i++) t[i] = 0;

  t[0] = w0[0];
  t[1] = w0[1];

  const u32 salt_len = (hc->salt_len < SAPB_SALT_BYTES) ? hc->salt_len : SAPB_SALT_BYTES;

  for (u32 i = 0; i < salt_len; i++) pcfg_put_byte (t, len + i, pcfg_get_byte (hc->s, i));

  const u32 pw_salt_len = len + hc->salt_len;

  t[14] = pw_salt_len * 8;
  t[15] = 0;

  append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, pw_salt_len);

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

  const u32 sum20 = walld0rf_magic (w0, len, hc->s, hc->salt_len, digest[0], digest[1], digest[2], digest[3], t, s_bcode);

  append_0x80_4x4_S (t + 0, t + 4, t + 8, t + 12, sum20);

  t[14] = sum20 * 8;
  t[15] = 0;

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (t + 0, t + 4, t + 8, t + 12, digest);

  dgst[0] = digest[0] ^ digest[2];
  dgst[1] = 0;
  dgst[2] = 0;
  dgst[3] = 0;

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 8) return false; // otherwise it overflows in waldorf function

  return pcfg_sapb (w, len, dgst, hc);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 8) return false; // otherwise it overflows in waldorf function

  u32 t[2];

  for (u32 i = 0; i < 2; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_sapb (t, len, dgst, hc);
}

#define PCFG_KERNEL_MXX m07701_mxx
#define PCFG_KERNEL_SXX m07701_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
