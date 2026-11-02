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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_des.cl)
#include M2S(INCLUDE_PATH/inc_krb5_encpart_des.cl)
#endif

#ifdef REAL_SHM
#define PCFG_HASH_SHARED_DECL          \
  LOCAL_VK u32 s_SPtrans[8][64];       \
  LOCAL_VK u32 s_skb[8][64];           \
  for (u32 i = lid; i < 64; i += lsz)  \
  {                                    \
    s_SPtrans[0][i] = c_SPtrans[0][i]; \
    s_SPtrans[1][i] = c_SPtrans[1][i]; \
    s_SPtrans[2][i] = c_SPtrans[2][i]; \
    s_SPtrans[3][i] = c_SPtrans[3][i]; \
    s_SPtrans[4][i] = c_SPtrans[4][i]; \
    s_SPtrans[5][i] = c_SPtrans[5][i]; \
    s_SPtrans[6][i] = c_SPtrans[6][i]; \
    s_SPtrans[7][i] = c_SPtrans[7][i]; \
    s_skb[0][i] = c_skb[0][i];         \
    s_skb[1][i] = c_skb[1][i];         \
    s_skb[2][i] = c_skb[2][i];         \
    s_skb[3][i] = c_skb[3][i];         \
    s_skb[4][i] = c_skb[4][i];         \
    s_skb[5][i] = c_skb[5][i];         \
    s_skb[6][i] = c_skb[6][i];         \
    s_skb[7][i] = c_skb[7][i];         \
  }                                    \
  SYNC_THREADS ();

#define PCFG_HASH_SHARED_BIND(hc) \
  (hc)->s_SPtrans = s_SPtrans;    \
  (hc)->s_skb = s_skb;
#endif

typedef struct krb5tgs_3
{
  u32 account_info[512];

  u32 salt_buf[32];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_3_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (krb5tgs_3_t)

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  GLOBAL_AS const krb5tgs_3_t *esalt_bufs;

  u32 digest_pos;
  u32 salt_len;

  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const krb5tgs_3_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  hc->esalt_bufs = esalt_bufs;
  hc->digest_pos = digest_pos;
  hc->salt_len   = esalt_bufs[digest_pos].salt_len;
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  // w is the caller's candidate buffer, reused for the next candidate and only PCFG_ARRAY_WORDS
  // long, so the password and the salt are joined in a buffer of our own

  u32 t[64];

  krb5_des_build_buf (w, len, hc->esalt_bufs[hc->digest_pos].salt_buf, hc->salt_len, t);

  u32 key[2];

  krb5_des_string_to_key (t, len + hc->salt_len, key, s_SPtrans, s_skb);

  if (krb5_des_encpart_check (key, hc->esalt_bufs[hc->digest_pos].checksum, hc->esalt_bufs[hc->digest_pos].edata2, hc->esalt_bufs[hc->digest_pos].edata2_len, false, s_SPtrans, s_skb) == false) return false;

  // the check is a yes or no, so the digest the host is looking for is handed back unchanged

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 t[64];

  for (u32 i = 0; i < 64; i++) t[i] = w[i];

  const bool ok = pcfg_hash (hc, t, len, dgst);

  return ok;
}

#define PCFG_KERNEL_MXX m38500_mxx
#define PCFG_KERNEL_SXX m38500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
