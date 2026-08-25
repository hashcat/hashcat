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

typedef struct tacacs_plus
{
  u32 session_buf[16];

  u32 ct_data_buf[64];
  u32 ct_data_len;

  u32 sequence_buf[16];

} tacacs_plus_t;

#define PCFG_KERN_ATTR      KERN_ATTR_PCFG_ESALT (tacacs_plus_t)

typedef struct pcfg_hash_ctx
{
  u32 search[4];

  md5_ctx_t ctx0;

  u32 ct_buf[2];
  u32 ct_len;

  u32 sequence_buf0;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, GLOBAL_AS const tacacs_plus_t *esalt_bufs, GLOBAL_AS const digest_t *digests_buf, const u32 digest_pos)
{
  hc->search[0] = digests_buf[digest_pos].digest_buf[0];
  hc->search[1] = digests_buf[digest_pos].digest_buf[1];
  hc->search[2] = digests_buf[digest_pos].digest_buf[2];
  hc->search[3] = digests_buf[digest_pos].digest_buf[3];

  md5_init (&hc->ctx0);

  u32 session0[4];
  u32 session1[4];
  u32 session2[4];
  u32 session3[4];

  session0[0] = esalt_bufs[digest_pos].session_buf[0];
  session0[1] = 0;
  session0[2] = 0;
  session0[3] = 0;
  session1[0] = 0;
  session1[1] = 0;
  session1[2] = 0;
  session1[3] = 0;
  session2[0] = 0;
  session2[1] = 0;
  session2[2] = 0;
  session2[3] = 0;
  session3[0] = 0;
  session3[1] = 0;
  session3[2] = 0;
  session3[3] = 0;

  md5_update_64 (&hc->ctx0, session0, session1, session2, session3, 4);

  hc->ct_buf[0] = esalt_bufs[digest_pos].ct_data_buf[0];
  hc->ct_buf[1] = esalt_bufs[digest_pos].ct_data_buf[1];

  hc->ct_len = esalt_bufs[digest_pos].ct_data_len;

  hc->sequence_buf0 = esalt_bufs[digest_pos].sequence_buf[0];
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_hash (PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx = hc->ctx0;

  md5_update (&ctx, w, len);

  u32 sequence0[4];
  u32 sequence1[4];
  u32 sequence2[4];
  u32 sequence3[4];

  sequence0[0] = hc->sequence_buf0;
  sequence0[1] = 0;
  sequence0[2] = 0;
  sequence0[3] = 0;
  sequence1[0] = 0;
  sequence1[1] = 0;
  sequence1[2] = 0;
  sequence1[3] = 0;
  sequence2[0] = 0;
  sequence2[1] = 0;
  sequence2[2] = 0;
  sequence2[3] = 0;
  sequence3[0] = 0;
  sequence3[1] = 0;
  sequence3[2] = 0;
  sequence3[3] = 0;

  md5_update_64 (&ctx, sequence0, sequence1, sequence2, sequence3, 2);

  md5_final (&ctx);

  u32 test[2];

  test[0] = ctx.h[0] ^ hc->ct_buf[0];
  test[1] = ctx.h[1] ^ hc->ct_buf[1];

  if (hc->sequence_buf0 == 0x01c0)
  {
    const u32 action          = ((test[0] >>  0) & 0xff);
    // can have more than predefined ones
    // const u32 priv_lvl        = ((test[0] >>  8) & 0xff);
    const u32 authen_type     = ((test[0] >> 16) & 0xff);
    const u32 authen_service  = ((test[0] >> 24) & 0xff);
    const u32 user_len        = ((test[1] >>  0) & 0xff);
    const u32 port_len        = ((test[1] >>  8) & 0xff);
    const u32 rem_addr_len    = ((test[1] >> 16) & 0xff);
    const u32 data_len        = ((test[1] >> 24) & 0xff);

    if ((action != 0x01) && (action != 0x02) && (action != 0x04)) return false;

    if (authen_type < 0x01) return false;
    if (authen_type > 0x06) return false;

    if (authen_service > 0x09) return false;

    if ((8 + user_len + port_len + rem_addr_len + data_len) != hc->ct_len) return false;
  }
  else if ((hc->sequence_buf0 == 0x03c0) || (hc->sequence_buf0 == 0x05c0))
  {
    const u32 msg_len   = ((test[0] >>  0) & 0xff) << 8
                        | ((test[0] >>  8) & 0xff) << 0;
    const u32 data_len  = ((test[0] >> 16) & 0xff) << 8
                        | ((test[0] >> 24) & 0xff) << 0;
    const u32 flags     = ((test[1] >>  0) & 0xff);

    if ((5 + msg_len) != hc->ct_len) return false;

    if (data_len != 0) return false;

    if (flags != 0) return false;
  }
  else
  {
    const u32 status    = ((test[0] >>  0) & 0xff);
    const u32 flags     = ((test[0] >>  8) & 0xff);
    const u32 msg_len   = ((test[0] >> 16) & 0xff) << 8
                        | ((test[0] >> 24) & 0xff) << 0;
    const u32 data_len  = ((test[1] >>  0) & 0xff) << 8
                        | ((test[1] >>  8) & 0xff) << 0;

    if ((status < 0x01) && (status != 0x21)) return false;
    if ((status > 0x07) && (status != 0x21)) return false;

    if ((flags != 0x01) && (flags != 0x00)) return false;

    if ((6 + msg_len + data_len) != hc->ct_len) return false;
  }

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

DECLSPEC bool pcfg_hash_global (PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  md5_ctx_t ctx = hc->ctx0;

  md5_update_global (&ctx, w, len);

  u32 sequence0[4];
  u32 sequence1[4];
  u32 sequence2[4];
  u32 sequence3[4];

  sequence0[0] = hc->sequence_buf0;
  sequence0[1] = 0;
  sequence0[2] = 0;
  sequence0[3] = 0;
  sequence1[0] = 0;
  sequence1[1] = 0;
  sequence1[2] = 0;
  sequence1[3] = 0;
  sequence2[0] = 0;
  sequence2[1] = 0;
  sequence2[2] = 0;
  sequence2[3] = 0;
  sequence3[0] = 0;
  sequence3[1] = 0;
  sequence3[2] = 0;
  sequence3[3] = 0;

  md5_update_64 (&ctx, sequence0, sequence1, sequence2, sequence3, 2);

  md5_final (&ctx);

  u32 test[2];

  test[0] = ctx.h[0] ^ hc->ct_buf[0];
  test[1] = ctx.h[1] ^ hc->ct_buf[1];

  if (hc->sequence_buf0 == 0x01c0)
  {
    const u32 action          = ((test[0] >>  0) & 0xff);
    // can have more than predefined ones
    // const u32 priv_lvl        = ((test[0] >>  8) & 0xff);
    const u32 authen_type     = ((test[0] >> 16) & 0xff);
    const u32 authen_service  = ((test[0] >> 24) & 0xff);
    const u32 user_len        = ((test[1] >>  0) & 0xff);
    const u32 port_len        = ((test[1] >>  8) & 0xff);
    const u32 rem_addr_len    = ((test[1] >> 16) & 0xff);
    const u32 data_len        = ((test[1] >> 24) & 0xff);

    if ((action != 0x01) && (action != 0x02) && (action != 0x04)) return false;

    if (authen_type < 0x01) return false;
    if (authen_type > 0x06) return false;

    if (authen_service > 0x09) return false;

    if ((8 + user_len + port_len + rem_addr_len + data_len) != hc->ct_len) return false;
  }
  else if ((hc->sequence_buf0 == 0x03c0) || (hc->sequence_buf0 == 0x05c0))
  {
    const u32 msg_len   = ((test[0] >>  0) & 0xff) << 8
                        | ((test[0] >>  8) & 0xff) << 0;
    const u32 data_len  = ((test[0] >> 16) & 0xff) << 8
                        | ((test[0] >> 24) & 0xff) << 0;
    const u32 flags     = ((test[1] >>  0) & 0xff);

    if ((5 + msg_len) != hc->ct_len) return false;

    if (data_len != 0) return false;

    if (flags != 0) return false;
  }
  else
  {
    const u32 status    = ((test[0] >>  0) & 0xff);
    const u32 flags     = ((test[0] >>  8) & 0xff);
    const u32 msg_len   = ((test[0] >> 16) & 0xff) << 8
                        | ((test[0] >> 24) & 0xff) << 0;
    const u32 data_len  = ((test[1] >>  0) & 0xff) << 8
                        | ((test[1] >>  8) & 0xff) << 0;

    if ((status < 0x01) && (status != 0x21)) return false;
    if ((status > 0x07) && (status != 0x21)) return false;

    if ((flags != 0x01) && (flags != 0x00)) return false;

    if ((6 + msg_len + data_len) != hc->ct_len) return false;
  }

  dgst[0] = hc->search[0];
  dgst[1] = hc->search[1];
  dgst[2] = hc->search[2];
  dgst[3] = hc->search[3];

  return true;
}

#define PCFG_KERNEL_MXX m16100_mxx
#define PCFG_KERNEL_SXX m16100_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
