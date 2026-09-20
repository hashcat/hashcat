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
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

#define MIN_NULL_BYTES 10

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 secondBlockData[8];
  u32 secondBlockLen;
  u32 rc4key[2];

} oldoffice34_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (oldoffice34_t)

#define PCFG_HASH_SHARED_DECL \
  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->S = S;                    \
  (hc)->lid = lid;

typedef struct pcfg_hash_ctx
{
  u32 salt_buf[4];
  u32 encryptedVerifier[4];

  u32 version;
  u32 secondBlockLen;

  GLOBAL_AS const oldoffice34_t *esalt_bufs;

  u32 digest_pos;

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, GLOBAL_AS const oldoffice34_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  hc->salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  hc->salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  hc->salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  hc->encryptedVerifier[0] = esalt_bufs[digest_pos].encryptedVerifier[0];
  hc->encryptedVerifier[1] = esalt_bufs[digest_pos].encryptedVerifier[1];
  hc->encryptedVerifier[2] = esalt_bufs[digest_pos].encryptedVerifier[2];
  hc->encryptedVerifier[3] = esalt_bufs[digest_pos].encryptedVerifier[3];

  hc->version        = esalt_bufs[digest_pos].version;
  hc->secondBlockLen = esalt_bufs[digest_pos].secondBlockLen;

  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_second_block (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *pass_hash)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = pass_hash[0];
  w0[1] = pass_hash[1];
  w0[2] = pass_hash[2];
  w0[3] = pass_hash[3];
  w1[0] = pass_hash[4];
  w1[1] = 0x01000000;
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (20 + 4) * 8;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  digest[0] = hc_swap32_S (digest[0]);
  digest[1] = hc_swap32_S (digest[1]);
  digest[2] = 0;
  digest[3] = 0;

  digest[1] &= 0xff; // only 40-bit key

  // second block decrypt:

  rc4_init_128 (hc->S, digest, hc->lid);

  u32 secondBlockData[4];

  secondBlockData[0] = hc->esalt_bufs[hc->digest_pos].secondBlockData[0];
  secondBlockData[1] = hc->esalt_bufs[hc->digest_pos].secondBlockData[1];
  secondBlockData[2] = hc->esalt_bufs[hc->digest_pos].secondBlockData[2];
  secondBlockData[3] = hc->esalt_bufs[hc->digest_pos].secondBlockData[3];

  u32 out[4];

  u8 j = rc4_next_16 (hc->S, 0, 0, secondBlockData, out, hc->lid);

  int null_bytes = 0;

  for (int k = 0; k < 4; k++)
  {
    if ((out[k] & 0x000000ff) == 0) null_bytes++;
    if ((out[k] & 0x0000ff00) == 0) null_bytes++;
    if ((out[k] & 0x00ff0000) == 0) null_bytes++;
    if ((out[k] & 0xff000000) == 0) null_bytes++;
  }

  secondBlockData[0] = hc->esalt_bufs[hc->digest_pos].secondBlockData[4];
  secondBlockData[1] = hc->esalt_bufs[hc->digest_pos].secondBlockData[5];
  secondBlockData[2] = hc->esalt_bufs[hc->digest_pos].secondBlockData[6];
  secondBlockData[3] = hc->esalt_bufs[hc->digest_pos].secondBlockData[7];

  rc4_next_16 (hc->S, 16, j, secondBlockData, out, hc->lid);

  for (int k = 0; k < 4; k++)
  {
    if ((out[k] & 0x000000ff) == 0) null_bytes++;
    if ((out[k] & 0x0000ff00) == 0) null_bytes++;
    if ((out[k] & 0x00ff0000) == 0) null_bytes++;
    if ((out[k] & 0xff000000) == 0) null_bytes++;
  }

  return (null_bytes >= MIN_NULL_BYTES);
}

DECLSPEC bool pcfg_oldoffice34 (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[8];

  t[0] = w[0];
  t[1] = w[1];
  t[2] = w[2];
  t[3] = w[3];
  t[4] = w[4];
  t[5] = 0;
  t[6] = 0;
  t[7] = 0;

  pcfg_put_byte (t, len, 0x80);

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  make_utf16le_S (&t[4], w2, w3);
  make_utf16le_S (&t[0], w0, w1);

  const u32 pw_salt_len = (len * 2) + 16;

  w3[3] = pw_salt_len * 8;
  w3[2] = 0;
  w3[1] = hc_swap32_S (w2[1]);
  w3[0] = hc_swap32_S (w2[0]);
  w2[3] = hc_swap32_S (w1[3]);
  w2[2] = hc_swap32_S (w1[2]);
  w2[1] = hc_swap32_S (w1[1]);
  w2[0] = hc_swap32_S (w1[0]);
  w1[3] = hc_swap32_S (w0[3]);
  w1[2] = hc_swap32_S (w0[2]);
  w1[1] = hc_swap32_S (w0[1]);
  w1[0] = hc_swap32_S (w0[0]);
  w0[3] = hc->salt_buf[3];
  w0[2] = hc->salt_buf[2];
  w0[1] = hc->salt_buf[1];
  w0[0] = hc->salt_buf[0];

  u32 pass_hash[5];

  pass_hash[0] = SHA1M_A;
  pass_hash[1] = SHA1M_B;
  pass_hash[2] = SHA1M_C;
  pass_hash[3] = SHA1M_D;
  pass_hash[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, pass_hash);

  // the key for block zero, which is the block the encrypted verifier sits in

  w0[0] = pass_hash[0];
  w0[1] = pass_hash[1];
  w0[2] = pass_hash[2];
  w0[3] = pass_hash[3];
  w1[0] = pass_hash[4];
  w1[1] = 0;
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (20 + 4) * 8;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  digest[0] = hc_swap32_S (digest[0]);
  digest[1] = hc_swap32_S (digest[1]);
  digest[2] = hc_swap32_S (digest[2]);
  digest[3] = hc_swap32_S (digest[3]);

  if (hc->version == 3)
  {
    digest[1] &= 0xff;
    digest[2]  = 0;
    digest[3]  = 0;
  }

  rc4_init_128 (hc->S, digest, hc->lid);

  u32 out[4];

  u8 j = rc4_next_16 (hc->S, 0, 0, hc->encryptedVerifier, out, hc->lid);

  w0[0] = hc_swap32_S (out[0]);
  w0[1] = hc_swap32_S (out[1]);
  w0[2] = hc_swap32_S (out[2]);
  w0[3] = hc_swap32_S (out[3]);
  w1[0] = 0x80000000;
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
  w3[3] = 16 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  digest[0] = hc_swap32_S (digest[0]);
  digest[1] = hc_swap32_S (digest[1]);
  digest[2] = hc_swap32_S (digest[2]);
  digest[3] = hc_swap32_S (digest[3]);

  rc4_next_16 (hc->S, 16, j, digest, out, hc->lid);

  dgst[0] = out[0];
  dgst[1] = out[1];
  dgst[2] = out[2];
  dgst[3] = out[3];

  if (hc->secondBlockLen != 0)
  {
    if (pcfg_second_block (hc, pass_hash) == false) return false;
  }

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 19) return false;

  return pcfg_oldoffice34 (hc, w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > 19) return false;

  u32 t[5];

  for (u32 i = 0; i < 5; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_oldoffice34 (hc, t, len, dgst);
}

#define PCFG_KERNEL_MXX m09800_mxx
#define PCFG_KERNEL_SXX m09800_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
