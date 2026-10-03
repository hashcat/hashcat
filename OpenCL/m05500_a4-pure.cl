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
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

DECLSPEC void transform_netntlmv1_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *out)
{
  u32 t[8];

  t[0] = (w0 >>  0) & 0xff;
  t[1] = (w0 >>  8) & 0xff;
  t[2] = (w0 >> 16) & 0xff;
  t[3] = (w0 >> 24) & 0xff;
  t[4] = (w1 >>  0) & 0xff;
  t[5] = (w1 >>  8) & 0xff;
  t[6] = (w1 >> 16) & 0xff;
  t[7] = (w1 >> 24) & 0xff;

  u32 k[8];

  k[0] =               (t[0] >> 0);
  k[1] = (t[0] << 7) | (t[1] >> 1);
  k[2] = (t[1] << 6) | (t[2] >> 2);
  k[3] = (t[2] << 5) | (t[3] >> 3);
  k[4] = (t[3] << 4) | (t[4] >> 4);
  k[5] = (t[4] << 3) | (t[5] >> 5);
  k[6] = (t[5] << 2) | (t[6] >> 6);
  k[7] = (t[6] << 1);

  out[0] = ((k[0] & 0xff) <<  0)
         | ((k[1] & 0xff) <<  8)
         | ((k[2] & 0xff) << 16)
         | ((k[3] & 0xff) << 24);

  out[1] = ((k[4] & 0xff) <<  0)
         | ((k[5] & 0xff) <<  8)
         | ((k[6] & 0xff) << 16)
         | ((k[7] & 0xff) << 24);
}

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

typedef struct pcfg_hash_ctx
{
  u32 s0;
  u32 s1;
  u32 s2;
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64];
  LOCAL_AS u32 (*s_skb)[64];
  #endif

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, GLOBAL_AS const salt_t *salt_bufs, const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
  hc->s0 = salt_bufs[salt_pos].salt_buf[0];

  hc->s1 = salt_bufs[salt_pos].salt_buf[1];

  hc->s2 = salt_bufs[salt_pos].salt_buf[2];
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

  md4_ctx_t ctx;

  md4_init (&ctx);

  md4_update_utf16le (&ctx, w, len);

  md4_final (&ctx);

  const u32 a = ctx.h[0];
  const u32 b = ctx.h[1];
  const u32 c = ctx.h[2];
  const u32 d = ctx.h[3];

  if ((d >> 16) != hc->s2) return false;

  u32 key[2];

  transform_netntlmv1_key (a, b, key);

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 data[2];

  data[0] = hc->s0;
  data[1] = hc->s1;

  u32 out1[2];

  _des_crypt_encrypt_lm (out1, data, Kc, Kd, s_SPtrans);

  transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 out2[2];

  _des_crypt_encrypt_lm (out2, data, Kc, Kd, s_SPtrans);

  dgst[0] = out1[0];
  dgst[1] = out1[1];
  dgst[2] = out2[0];
  dgst[3] = out2[1];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  #ifdef REAL_SHM
  LOCAL_AS u32 (*s_SPtrans)[64] = hc->s_SPtrans;
  LOCAL_AS u32 (*s_skb)[64] = hc->s_skb;
  #else
  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64] = c_skb;
  #endif

  md4_ctx_t ctx;

  md4_init (&ctx);

  md4_update_global_utf16le (&ctx, w, len);

  md4_final (&ctx);

  const u32 a = ctx.h[0];
  const u32 b = ctx.h[1];
  const u32 c = ctx.h[2];
  const u32 d = ctx.h[3];

  if ((d >> 16) != hc->s2) return false;

  u32 key[2];

  transform_netntlmv1_key (a, b, key);

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 data[2];

  data[0] = hc->s0;
  data[1] = hc->s1;

  u32 out1[2];

  _des_crypt_encrypt_lm (out1, data, Kc, Kd, s_SPtrans);

  transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

  _des_crypt_keysetup_lm (key[0], key[1], Kc, Kd, s_skb);

  u32 out2[2];

  _des_crypt_encrypt_lm (out2, data, Kc, Kd, s_SPtrans);

  dgst[0] = out1[0];
  dgst[1] = out1[1];
  dgst[2] = out2[0];
  dgst[3] = out2[1];

  return true;
}

#define PCFG_KERNEL_MXX m05500_mxx
#define PCFG_KERNEL_SXX m05500_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
