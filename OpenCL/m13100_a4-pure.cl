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

typedef struct krb5tgs
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;

} krb5tgs_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (krb5tgs_t)

#define PCFG_HASH_SHARED_DECL \
  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->S = S;                    \
  (hc)->lid = lid;

DECLSPEC int decrypt_and_check (LOCAL_AS u32 *S, PRIVATE_AS u32 *data, GLOBAL_AS const u32 *edata2, const u32 edata2_len, PRIVATE_AS const u32 *K2, PRIVATE_AS const u32 *checksum, const u64 lid)
{
  rc4_init_128 (S, data, lid);

  u32 out0[4];
  u32 out1[4];

  u8 i = 0;
  u8 j = 0;

  /*
    8 first bytes are nonce, then ASN1 structs (DER encoding: type-length-data)

    if length >= 128 bytes:
        length is on 2 bytes and type is \x63\x82 (encode_krb5_enc_tkt_part) and data is an ASN1 sequence \x30\x82
    else:
        length is on 1 byte and type is \x63\x81 and data is an ASN1 sequence \x30\x81

    next headers follow the same ASN1 "type-length-data" scheme
  */

  j = rc4_next_16_global (S, i, j, edata2 + 0, out0, lid); i += 16;

  if (((out0[2] & 0xff00ffff) != 0x30008163) && ((out0[2] & 0x0000ffff) != 0x00008263)) return 0;

  j = rc4_next_16_global (S, i, j, edata2 + 4, out1, lid); i += 16;

  if (((out1[0] & 0x00ffffff) != 0x00000503) && (out1[0] != 0x050307A0)) return 0;

  rc4_init_128 (S, data, lid);

  i = 0;
  j = 0;

  // init hmac

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = K2[0];
  w0[1] = K2[1];
  w0[2] = K2[2];
  w0[3] = K2[3];
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

  int edata2_left;

  for (edata2_left = edata2_len; edata2_left >= 64; edata2_left -= 64)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;

    md5_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 0;
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

  if (edata2_left < 16)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w0, edata2_left & 0xf);
  }
  else if (edata2_left < 32)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w1, edata2_left & 0xf);
  }
  else if (edata2_left < 48)
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w2, edata2_left & 0xf);
  }
  else
  {
    j = rc4_next_16_global (S, i, j, edata2, w0, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w1, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w2, lid); i += 16; edata2 += 4;
    j = rc4_next_16_global (S, i, j, edata2, w3, lid); i += 16; edata2 += 4;

    truncate_block_4x4_le_S (w3, edata2_left & 0xf);
  }

  md5_hmac_update_64 (&ctx, w0, w1, w2, w3, edata2_left);

  md5_hmac_final (&ctx);

  if (checksum[0] != ctx.opad.h[0]) return 0;
  if (checksum[1] != ctx.opad.h[1]) return 0;
  if (checksum[2] != ctx.opad.h[2]) return 0;
  if (checksum[3] != ctx.opad.h[3]) return 0;

  return 1;
}

DECLSPEC void kerb_prepare (PRIVATE_AS const u32 *K, PRIVATE_AS const u32 *checksum, PRIVATE_AS u32 *digest, PRIVATE_AS u32 *K2)
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

  w0[0] = 2;
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

  K2[0] = ctx1.opad.h[0];
  K2[1] = ctx1.opad.h[1];
  K2[2] = ctx1.opad.h[2];
  K2[3] = ctx1.opad.h[3];
}

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  u32 checksum[4];

  GLOBAL_AS const krb5tgs_t *esalt_bufs;

  u32 digest_pos;

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const krb5tgs_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->checksum[0] = esalt_bufs[digest_pos].checksum[0];
  hc->checksum[1] = esalt_bufs[digest_pos].checksum[1];
  hc->checksum[2] = esalt_bufs[digest_pos].checksum[2];
  hc->checksum[3] = esalt_bufs[digest_pos].checksum[3];

  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
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

  u32 K2[4];

  kerb_prepare (ctx.h, hc->checksum, digest, K2);

  if (decrypt_and_check (hc->S, digest, hc->esalt_bufs[hc->digest_pos].edata2, hc->esalt_bufs[hc->digest_pos].edata2_len, K2, hc->checksum, hc->lid) == 0) return false;

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64] = { 0 };

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool r = pcfg_hash (hc, t, len, dgst);

  return r;
}

#define PCFG_KERNEL_MXX m13100_mxx
#define PCFG_KERNEL_SXX m13100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
