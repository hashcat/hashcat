/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

// The decrypted data is already private and needs no decryption as it is read, so the decoder can
// keep its one byte dictionary. See the comment on M_DICT_SIZE in inc_zip_inflate.cl.

#define INFLATE_SMALL_DICT

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_zip_inflate.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct dashlane
{
  u32 type;
  u32 data_buf[32];

} dashlane_t;

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

// The first 128 bytes of a Dashlane .aes file or .dash archive, decrypted with AES-256-CBC, hold a
// 4 byte length, a 2 byte zlib header and then raw deflate. Inflating from byte 6 gives the start
// of the XML, which is what the password is verified against. Only the first bytes of the stream
// decode before it runs out of input, which is enough: the marker sits at the front.

#define DASHLANE_PT_LEN     128
#define DASHLANE_SKIP       6
#define DASHLANE_MARKER_LEN 13

// the marker sits at the front of the inflated text, so a short scan over it is enough

#define DASHLANE_SCAN_LEN   64

DECLSPEC int dashlane_has_marker (PRIVATE_AS const u8 *buf, const int len)
{
  const u8 marker[DASHLANE_MARKER_LEN] = { '<', '?', 'x', 'm', 'l', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n' };

  for (int i = 0; (i + DASHLANE_MARKER_LEN) <= len; i++)
  {
    int hit = 1;

    for (int j = 0; j < DASHLANE_MARKER_LEN; j++)
    {
      if (buf[i + j] != marker[j])
      {
        hit = 0;

        break;
      }
    }

    if (hit == 1) return 1;
  }

  return 0;
}

KERNEL_FQ KERNEL_FA void m34900_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, dashlane_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ KERNEL_FA void m34900_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, dashlane_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  for (u32 i = 0; i < 8; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

KERNEL_FQ KERNEL_FA void m34900_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, dashlane_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  u32 pkey[8];

  pkey[0] = tmps[gid].out[0];
  pkey[1] = tmps[gid].out[1];
  pkey[2] = tmps[gid].out[2];
  pkey[3] = tmps[gid].out[3];
  pkey[4] = tmps[gid].out[4];
  pkey[5] = tmps[gid].out[5];
  pkey[6] = tmps[gid].out[6];
  pkey[7] = tmps[gid].out[7];

  // EVP_BytesToKey with SHA-1 and one round over the PBKDF2 output and the first 8 bytes of the
  // salt. Three passes give 60 bytes, of which bytes 0 to 31 are its key and 32 to 47 its IV.
  // Dashlane type 1 encrypts with the PBKDF2 output and uses only this IV, type 0 uses the key.

  u32 s8[2];

  s8[0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[0]);
  s8[1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[1]);

  u32 d[15];

  for (int round = 0; round < 3; round++)
  {
    sha1_ctx_t ctx;

    sha1_init (&ctx);

    if (round > 0)
    {
      u32 prev[16] = { 0 };

      prev[0] = d[((round - 1) * 5) + 0];
      prev[1] = d[((round - 1) * 5) + 1];
      prev[2] = d[((round - 1) * 5) + 2];
      prev[3] = d[((round - 1) * 5) + 3];
      prev[4] = d[((round - 1) * 5) + 4];

      sha1_update (&ctx, prev, 20);
    }

    u32 body[16] = { 0 };

    body[0] = pkey[0];
    body[1] = pkey[1];
    body[2] = pkey[2];
    body[3] = pkey[3];
    body[4] = pkey[4];
    body[5] = pkey[5];
    body[6] = pkey[6];
    body[7] = pkey[7];
    body[8] = s8[0];
    body[9] = s8[1];

    sha1_update (&ctx, body, 40);

    sha1_final (&ctx);

    d[(round * 5) + 0] = ctx.h[0];
    d[(round * 5) + 1] = ctx.h[1];
    d[(round * 5) + 2] = ctx.h[2];
    d[(round * 5) + 3] = ctx.h[3];
    d[(round * 5) + 4] = ctx.h[4];
  }

  // the IV is bytes 32 to 47 of that stream, so the last 8 bytes of the second pass and the first
  // 8 of the third

  u32 iv[4];

  iv[0] = d[8];
  iv[1] = d[9];
  iv[2] = d[10];
  iv[3] = d[11];

  u32 ukey[8];

  if (esalt_bufs[DIGESTS_OFFSET_HOST].type == 1)
  {
    ukey[0] = pkey[0];
    ukey[1] = pkey[1];
    ukey[2] = pkey[2];
    ukey[3] = pkey[3];
    ukey[4] = pkey[4];
    ukey[5] = pkey[5];
    ukey[6] = pkey[6];
    ukey[7] = pkey[7];
  }
  else
  {
    ukey[0] = d[0];
    ukey[1] = d[1];
    ukey[2] = d[2];
    ukey[3] = d[3];
    ukey[4] = d[4];
    ukey[5] = d[5];
    ukey[6] = d[6];
    ukey[7] = d[7];
  }

  u32 ks[60];

  AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  // AES-256-CBC over the first 128 bytes

  u32 pt[32];

  u32 cbc[4];

  cbc[0] = iv[0];
  cbc[1] = iv[1];
  cbc[2] = iv[2];
  cbc[3] = iv[3];

  for (int i = 0; i < 32; i += 4)
  {
    u32 ct[4];

    ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[i + 0];
    ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[i + 1];
    ct[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[i + 2];
    ct[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[i + 3];

    u32 out[4];

    AES256_decrypt (ks, ct, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt[i + 0] = out[0] ^ cbc[0];
    pt[i + 1] = out[1] ^ cbc[1];
    pt[i + 2] = out[2] ^ cbc[2];
    pt[i + 3] = out[3] ^ cbc[3];

    cbc[0] = ct[0];
    cbc[1] = ct[1];
    cbc[2] = ct[2];
    cbc[3] = ct[3];
  }

  u8 pt_buf[DASHLANE_PT_LEN];

  for (int i = 0; i < 32; i++)
  {
    pt_buf[(i * 4) + 0] = (u8) (pt[i] >> 24);
    pt_buf[(i * 4) + 1] = (u8) (pt[i] >> 16);
    pt_buf[(i * 4) + 2] = (u8) (pt[i] >>  8);
    pt_buf[(i * 4) + 3] = (u8) (pt[i] >>  0);
  }

  int found = 0;

  if (esalt_bufs[DIGESTS_OFFSET_HOST].type == 1)
  {
    // the decoder wraps back to the start of the output buffer itself and resolves back references
    // out of it, so the buffer has to be one dictionary wide whatever the scan above reads. See the
    // comment on TINFL_FLAG_FLUSH_WINDOW in inc_zip_inflate.cl.

    u8 xml_buf[TINFL_LZ_DICT_SIZE];

    inflate_state pStream;

    mz_stream infstream;

    infstream.next_in   = pt_buf + DASHLANE_SKIP;
    infstream.avail_in  = DASHLANE_PT_LEN - DASHLANE_SKIP;
    infstream.next_out  = xml_buf;
    infstream.avail_out = TINFL_LZ_DICT_SIZE;
    infstream.opaque    = Z_NULL;

    mz_inflateInit2 (&infstream, -MAX_WBITS, &pStream);

    // the stream is cut off after 128 bytes of input, so it ends in a data error once it runs out
    // of them. What it produced before that is kept, the same as zlib leaves it.

    hc_inflate (&infstream);

    int scan_len = (int) infstream.total_out;

    if (scan_len > DASHLANE_SCAN_LEN) scan_len = DASHLANE_SCAN_LEN;

    found = dashlane_has_marker (xml_buf, scan_len);
  }
  else
  {
    found = dashlane_has_marker (pt_buf, DASHLANE_PT_LEN);
  }

  if (found == 0) return;

  const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
  const u32 r2 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
  const u32 r3 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
