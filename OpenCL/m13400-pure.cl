/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#include "inc_cipher_twofish.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__kernel void m13400_init (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  if (esalt_bufs[digests_offset].version == 2 && esalt_bufs[digests_offset].keyfile_len == 0)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  if (esalt_bufs[digests_offset].keyfile_len != 0)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = esalt_bufs[digests_offset].keyfile[0];
    w2[1] = esalt_bufs[digests_offset].keyfile[1];
    w2[2] = esalt_bufs[digests_offset].keyfile[2];
    w2[3] = esalt_bufs[digests_offset].keyfile[3];
    w3[0] = esalt_bufs[digests_offset].keyfile[4];
    w3[1] = esalt_bufs[digests_offset].keyfile[5];
    w3[2] = esalt_bufs[digests_offset].keyfile[6];
    w3[3] = esalt_bufs[digests_offset].keyfile[7];

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  tmps[gid].tmp_digest[0] = digest[0];
  tmps[gid].tmp_digest[1] = digest[1];
  tmps[gid].tmp_digest[2] = digest[2];
  tmps[gid].tmp_digest[3] = digest[3];
  tmps[gid].tmp_digest[4] = digest[4];
  tmps[gid].tmp_digest[5] = digest[5];
  tmps[gid].tmp_digest[6] = digest[6];
  tmps[gid].tmp_digest[7] = digest[7];
}

__kernel void m13400_loop (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /* Construct AES key */

  u32 ukey[8];

  ukey[0] = esalt_bufs[digests_offset].transf_random_seed[0];
  ukey[1] = esalt_bufs[digests_offset].transf_random_seed[1];
  ukey[2] = esalt_bufs[digests_offset].transf_random_seed[2];
  ukey[3] = esalt_bufs[digests_offset].transf_random_seed[3];
  ukey[4] = esalt_bufs[digests_offset].transf_random_seed[4];
  ukey[5] = esalt_bufs[digests_offset].transf_random_seed[5];
  ukey[6] = esalt_bufs[digests_offset].transf_random_seed[6];
  ukey[7] = esalt_bufs[digests_offset].transf_random_seed[7];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 data0[4];
  u32 data1[4];

  data0[0] = tmps[gid].tmp_digest[0];
  data0[1] = tmps[gid].tmp_digest[1];
  data0[2] = tmps[gid].tmp_digest[2];
  data0[3] = tmps[gid].tmp_digest[3];
  data1[0] = tmps[gid].tmp_digest[4];
  data1[1] = tmps[gid].tmp_digest[5];
  data1[2] = tmps[gid].tmp_digest[6];
  data1[3] = tmps[gid].tmp_digest[7];

  for (u32 i = 0; i < loop_cnt; i++)
  {
    AES256_encrypt (ks, data0, data0, s_te0, s_te1, s_te2, s_te3, s_te4);
    AES256_encrypt (ks, data1, data1, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  tmps[gid].tmp_digest[0] = data0[0];
  tmps[gid].tmp_digest[1] = data0[1];
  tmps[gid].tmp_digest[2] = data0[2];
  tmps[gid].tmp_digest[3] = data0[3];
  tmps[gid].tmp_digest[4] = data1[0];
  tmps[gid].tmp_digest[5] = data1[1];
  tmps[gid].tmp_digest[6] = data1[2];
  tmps[gid].tmp_digest[7] = data1[3];
}

__kernel void m13400_comp (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /* hash output... */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = tmps[gid].tmp_digest[0];
  w0[1] = tmps[gid].tmp_digest[1];
  w0[2] = tmps[gid].tmp_digest[2];
  w0[3] = tmps[gid].tmp_digest[3];
  w1[0] = tmps[gid].tmp_digest[4];
  w1[1] = tmps[gid].tmp_digest[5];
  w1[2] = tmps[gid].tmp_digest[6];
  w1[3] = tmps[gid].tmp_digest[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  /* ...then hash final_random_seed | output */

  if (esalt_bufs[digests_offset].version == 1)
  {
    w0[0] = esalt_bufs[digests_offset].final_random_seed[0];
    w0[1] = esalt_bufs[digests_offset].final_random_seed[1];
    w0[2] = esalt_bufs[digests_offset].final_random_seed[2];
    w0[3] = esalt_bufs[digests_offset].final_random_seed[3];
    w1[0] = digest[0];
    w1[1] = digest[1];
    w1[2] = digest[2];
    w1[3] = digest[3];
    w2[0] = digest[4];
    w2[1] = digest[5];
    w2[2] = digest[6];
    w2[3] = digest[7];
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 48);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }
  else
  {
    w0[0] = esalt_bufs[digests_offset].final_random_seed[0];
    w0[1] = esalt_bufs[digests_offset].final_random_seed[1];
    w0[2] = esalt_bufs[digests_offset].final_random_seed[2];
    w0[3] = esalt_bufs[digests_offset].final_random_seed[3];
    w1[0] = esalt_bufs[digests_offset].final_random_seed[4];
    w1[1] = esalt_bufs[digests_offset].final_random_seed[5];
    w1[2] = esalt_bufs[digests_offset].final_random_seed[6];
    w1[3] = esalt_bufs[digests_offset].final_random_seed[7];
    w2[0] = digest[0];
    w2[1] = digest[1];
    w2[2] = digest[2];
    w2[3] = digest[3];
    w3[0] = digest[4];
    w3[1] = digest[5];
    w3[2] = digest[6];
    w3[3] = digest[7];

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  // at this point we have to distinguish between the different keypass versions

  u32 iv[4];

  iv[0] = esalt_bufs[digests_offset].enc_iv[0];
  iv[1] = esalt_bufs[digests_offset].enc_iv[1];
  iv[2] = esalt_bufs[digests_offset].enc_iv[2];
  iv[3] = esalt_bufs[digests_offset].enc_iv[3];

  u32 r0 = 0;
  u32 r1 = 0;
  u32 r2 = 0;
  u32 r3 = 0;

  if (esalt_bufs[digests_offset].version == 1)
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    if (esalt_bufs[digests_offset].algorithm == 1)
    {
      /* Construct final Twofish key */
      u32 sk[4];
      u32 lk[40];

      digest[0] = swap32_S (digest[0]);
      digest[1] = swap32_S (digest[1]);
      digest[2] = swap32_S (digest[2]);
      digest[3] = swap32_S (digest[3]);
      digest[4] = swap32_S (digest[4]);
      digest[5] = swap32_S (digest[5]);
      digest[6] = swap32_S (digest[6]);
      digest[7] = swap32_S (digest[7]);

      twofish256_set_key (sk, lk, digest);

      iv[0] = swap32_S (iv[0]);
      iv[1] = swap32_S (iv[1]);
      iv[2] = swap32_S (iv[2]);
      iv[3] = swap32_S (iv[3]);

      u32 contents_len = esalt_bufs[digests_offset].contents_len;

      u32 contents_pos;
      u32 contents_off;

      // process (decrypt and hash) the buffer with the biggest steps possible.

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 16; contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
        data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
        data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
        data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

        data[0] = swap32_S (data[0]);
        data[1] = swap32_S (data[1]);
        data[2] = swap32_S (data[2]);
        data[3] = swap32_S (data[3]);

        u32 out[4];

        twofish256_decrypt (sk, lk, data, out);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        out[0] = swap32_S (out[0]);
        out[1] = swap32_S (out[1]);
        out[2] = swap32_S (out[2]);
        out[3] = swap32_S (out[3]);

        u32 w0[4] = { 0 };
        u32 w1[4] = { 0 };
        u32 w2[4] = { 0 };
        u32 w3[4] = { 0 };

        w0[0] = out[0];
        w0[1] = out[1];
        w0[2] = out[2];
        w0[3] = out[3];

        sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
      data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
      data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
      data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

      data[0] = swap32_S (data[0]);
      data[1] = swap32_S (data[1]);
      data[2] = swap32_S (data[2]);
      data[3] = swap32_S (data[3]);

      u32 out[4];

      twofish256_decrypt (sk, lk, data, out);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      out[0] = swap32_S (out[0]);
      out[1] = swap32_S (out[1]);
      out[2] = swap32_S (out[2]);
      out[3] = swap32_S (out[3]);

      // now we can access the pad byte

      const u32 pad_byte = out[3] & 0xff;

      // we need to clear the buffer of the padding data

      truncate_block_4x4_be_S (out, 16 - pad_byte);

      u32 w0[4] = { 0 };
      u32 w1[4] = { 0 };
      u32 w2[4] = { 0 };
      u32 w3[4] = { 0 };

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];

      sha256_update_64 (&ctx, w0, w1, w2, w3, 16 - pad_byte);
    }
    else
    {
      /* Construct final AES key */

      #define KEYLEN 60

      u32 ks[KEYLEN];

      AES256_set_decrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

      u32 contents_len = esalt_bufs[digests_offset].contents_len;

      u32 contents_pos;
      u32 contents_off;

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 16; contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
        data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
        data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
        data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

        u32 out[4];

        AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        u32 w0[4] = { 0 };
        u32 w1[4] = { 0 };
        u32 w2[4] = { 0 };
        u32 w3[4] = { 0 };

        w0[0] = out[0];
        w0[1] = out[1];
        w0[2] = out[2];
        w0[3] = out[3];

        sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
      data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
      data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
      data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

      u32 out[4];

      AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // now we can access the pad byte

      const u32 pad_byte = out[3] & 0xff;

      // we need to clear the buffer of the padding data

      truncate_block_4x4_be_S (out, 16 - pad_byte);

      u32 w0[4] = { 0 };
      u32 w1[4] = { 0 };
      u32 w2[4] = { 0 };
      u32 w3[4] = { 0 };

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];

      sha256_update_64 (&ctx, w0, w1, w2, w3, 16 - pad_byte);
    }

    sha256_final (&ctx);

    r0 = ctx.h[0];
    r1 = ctx.h[1];
    r2 = ctx.h[2];
    r3 = ctx.h[3];
  }
  else
  {
    /* Construct final AES key */

    #define KEYLEN 60

    u32 ks[KEYLEN];

    AES256_set_decrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

    u32 data[4];

    data[0] = esalt_bufs[digests_offset].contents_hash[0];
    data[1] = esalt_bufs[digests_offset].contents_hash[1];
    data[2] = esalt_bufs[digests_offset].contents_hash[2];
    data[3] = esalt_bufs[digests_offset].contents_hash[3];

    u32 out[4];

    AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    r0 = out[0];
    r1 = out[1];
    r2 = out[2];
    r3 = out[3];
  }

  #define il_pos 0

  #include COMPARE_M
}
