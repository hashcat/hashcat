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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct krb5pa
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (krb5pa_t)

#define PCFG_HASH_SHARED_DECL \
  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->S = S;                    \
  (hc)->lid = lid;

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, PRIVATE_AS u32 *timestamp_ct, const u64 lid)
{
  rc4_init_128 (S, data, lid);

  u32 out[4];

  u8 j = 0;

  j = rc4_next_16 (S,  0, j, timestamp_ct + 0, out, lid);

  if ((out[3] & 0xffff0000) != 0x30320000) return 0;

  j = rc4_next_16 (S, 16, j, timestamp_ct + 4, out, lid);

  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0; out[0] >>= 8;
  if (((out[0] & 0xff) < '0') || ((out[0] & 0xff) > '9')) return 0;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0; out[1] >>= 8;
  if (((out[1] & 0xff) < '0') || ((out[1] & 0xff) > '9')) return 0;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0; out[2] >>= 8;
  if (((out[2] & 0xff) < '0') || ((out[2] & 0xff) > '9')) return 0;

  return 1;
}

DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *K, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest)
{
  // K1=MD5_HMAC(K,1); with 1 encoded as little indian on 4 bytes (01000000 in hexa);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = K[0];
  w0[1] = K[1];
  w0[2] = K[2];
  w0[3] = K[3];
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

  md5_hmac_ctx_t ctx1;

  md5_hmac_init_64 (&ctx1, w0, w1, w2, w3);

  w0[0] = 1;
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

  md5_hmac_update_64 (&ctx1, w0, w1, w2, w3, 4);

  md5_hmac_final (&ctx1);

  w0[0] = ctx1.opad.h[0];
  w0[1] = ctx1.opad.h[1];
  w0[2] = ctx1.opad.h[2];
  w0[3] = ctx1.opad.h[3];
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

  md5_hmac_ctx_t ctx;

  md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

  w0[0] = checksum[0];
  w0[1] = checksum[1];
  w0[2] = checksum[2];
  w0[3] = checksum[3];
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

  md5_hmac_update_64 (&ctx, w0, w1, w2, w3, 16);

  md5_hmac_final (&ctx);

  digest[0] = ctx.opad.h[0];
  digest[1] = ctx.opad.h[1];
  digest[2] = ctx.opad.h[2];
  digest[3] = ctx.opad.h[3];
}

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  u32 checksum[4];

  u32 timestamp_ct[8];

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const krb5pa_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->checksum[0] = esalt_bufs[digest_pos].checksum[0];
  hc->checksum[1] = esalt_bufs[digest_pos].checksum[1];
  hc->checksum[2] = esalt_bufs[digest_pos].checksum[2];
  hc->checksum[3] = esalt_bufs[digest_pos].checksum[3];

  hc->timestamp_ct[0] = esalt_bufs[digest_pos].timestamp[0];
  hc->timestamp_ct[1] = esalt_bufs[digest_pos].timestamp[1];
  hc->timestamp_ct[2] = esalt_bufs[digest_pos].timestamp[2];
  hc->timestamp_ct[3] = esalt_bufs[digest_pos].timestamp[3];
  hc->timestamp_ct[4] = esalt_bufs[digest_pos].timestamp[4];
  hc->timestamp_ct[5] = esalt_bufs[digest_pos].timestamp[5];
  hc->timestamp_ct[6] = esalt_bufs[digest_pos].timestamp[6];
  hc->timestamp_ct[7] = esalt_bufs[digest_pos].timestamp[7];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t ctx;

  md4_init (&ctx);

  md4_update_utf16le (&ctx, w, len);

  md4_final (&ctx);

  u32 digest[4];

  kerb_prepare (ctx.h, hc->checksum, digest);

  u32 timestamp_ct[8];

  timestamp_ct[0] = hc->timestamp_ct[0];
  timestamp_ct[1] = hc->timestamp_ct[1];
  timestamp_ct[2] = hc->timestamp_ct[2];
  timestamp_ct[3] = hc->timestamp_ct[3];
  timestamp_ct[4] = hc->timestamp_ct[4];
  timestamp_ct[5] = hc->timestamp_ct[5];
  timestamp_ct[6] = hc->timestamp_ct[6];
  timestamp_ct[7] = hc->timestamp_ct[7];

  if (decrypt_and_check (hc->S, digest, timestamp_ct, hc->lid) == 0) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md4_ctx_t ctx;

  md4_init (&ctx);

  md4_update_global_utf16le (&ctx, w, len);

  md4_final (&ctx);

  u32 digest[4];

  kerb_prepare (ctx.h, hc->checksum, digest);

  u32 timestamp_ct[8];

  timestamp_ct[0] = hc->timestamp_ct[0];
  timestamp_ct[1] = hc->timestamp_ct[1];
  timestamp_ct[2] = hc->timestamp_ct[2];
  timestamp_ct[3] = hc->timestamp_ct[3];
  timestamp_ct[4] = hc->timestamp_ct[4];
  timestamp_ct[5] = hc->timestamp_ct[5];
  timestamp_ct[6] = hc->timestamp_ct[6];
  timestamp_ct[7] = hc->timestamp_ct[7];

  if (decrypt_and_check (hc->S, digest, timestamp_ct, hc->lid) == 0) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

#define PCFG_KERNEL_MXX m07500_mxx
#define PCFG_KERNEL_SXX m07500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
