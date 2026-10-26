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
  u32 encryptedVerifier[4];

  LOCAL_AS u32 *S;

  u64 lid;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const oldoffice34_t *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->encryptedVerifier[0] = esalt_bufs[digest_pos].encryptedVerifier[0];
  hc->encryptedVerifier[1] = esalt_bufs[digest_pos].encryptedVerifier[1];
  hc->encryptedVerifier[2] = esalt_bufs[digest_pos].encryptedVerifier[2];
  hc->encryptedVerifier[3] = esalt_bufs[digest_pos].encryptedVerifier[3];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_oldoffice34 (PRIVATE_AS const u32 *w, PRIVATE_AS u32 *dgst, PRIVATE_AS const pcfg_hash_ctx_t *hc)
{
  u32 key[4];

  key[0] = w[0];
  key[1] = w[1] & 0xff;
  key[2] = 0;
  key[3] = 0;

  rc4_init_128 (hc->S, key, hc->lid);

  u32 out[4];

  u8 j = rc4_next_16 (hc->S, 0, 0, hc->encryptedVerifier, out, hc->lid);

  /**
   * sha1
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

  // the keystream carries on from where the verifier left it off, so i and j both continue

  rc4_next_16 (hc->S, 16, j, digest, out, hc->lid);

  dgst[0] = out[0];
  dgst[1] = out[1];
  dgst[2] = out[2];
  dgst[3] = out[3];

  return true;
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 5) return false;

  return pcfg_oldoffice34 (w, dgst, hc);
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len != 5) return false;

  u32 t[2];

  t[0] = w[0];
  t[1] = w[1];

  return pcfg_oldoffice34 (t, dgst, hc);
}

#define PCFG_KERNEL_MXX m09810_mxx
#define PCFG_KERNEL_SXX m09810_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
