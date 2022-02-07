/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
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

KERNEL_FQ void m16100_mxx (KERN_ATTR_RULES_ESALT (tacacs_plus_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  u32 session0[4];
  u32 session1[4];
  u32 session2[4];
  u32 session3[4];

  session0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].session_buf[0];
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

  md5_update_64 (&ctx0, session0, session1, session2, session3, 4);

  u32 ct_buf[2];

  ct_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_buf[0];
  ct_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_buf[1];

  u32 ct_len = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_len;

  u32 sequence_buf0 = esalt_bufs[DIGESTS_OFFSET_HOST].sequence_buf[0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx = ctx0;

    md5_update (&ctx, tmp.i, tmp.pw_len);

    u32 sequence0[4];
    u32 sequence1[4];
    u32 sequence2[4];
    u32 sequence3[4];

    sequence0[0] = sequence_buf0;
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

    test[0] = ctx.h[0] ^ ct_buf[0];
    test[1] = ctx.h[1] ^ ct_buf[1];

    if (sequence_buf0 == 0x01c0)
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

      if (((action == 0x01) || (action == 0x02) || (action == 0x04))
      &&  ((authen_type    >= 0x01) && (authen_type    <= 0x06))
      &&  ((authen_service >= 0x00) && (authen_service <= 0x09))
      &&  ((8 + user_len + port_len + rem_addr_len + data_len) == ct_len))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
    else if ((sequence_buf0 == 0x03c0) || (sequence_buf0 == 0x05c0))
    {
      const u32 msg_len   = ((test[0] >>  0) & 0xff) << 8
                          | ((test[0] >>  8) & 0xff) << 0;
      const u32 data_len  = ((test[0] >> 16) & 0xff) << 8
                          | ((test[0] >> 24) & 0xff) << 0;
      const u32 flags     = ((test[1] >>  0) & 0xff);

      if (((5 + msg_len) == ct_len)
       &&  (data_len == 0)
       &&  (flags == 0))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
    else
    {
      const u32 status    = ((test[0] >>  0) & 0xff);
      const u32 flags     = ((test[0] >>  8) & 0xff);
      const u32 msg_len   = ((test[0] >> 16) & 0xff) << 8
                          | ((test[0] >> 24) & 0xff) << 0;
      const u32 data_len  = ((test[1] >>  0) & 0xff) << 8
                          | ((test[1] >>  8) & 0xff) << 0;

      if (((status >= 0x01 && status <= 0x07) || status == 0x21)
       &&  (flags == 0x01 || flags == 0x00)
       &&  (6 + msg_len + data_len == ct_len))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ void m16100_sxx (KERN_ATTR_RULES_ESALT (tacacs_plus_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  u32 session0[4];
  u32 session1[4];
  u32 session2[4];
  u32 session3[4];

  session0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].session_buf[0];
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

  md5_update_64 (&ctx0, session0, session1, session2, session3, 4);

  u32 ct_buf[2];

  ct_buf[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_buf[0];
  ct_buf[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_buf[1];

  u32 ct_len = esalt_bufs[DIGESTS_OFFSET_HOST].ct_data_len;

  u32 sequence_buf0 = esalt_bufs[DIGESTS_OFFSET_HOST].sequence_buf[0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx = ctx0;

    md5_update (&ctx, tmp.i, tmp.pw_len);

    u32 sequence0[4];
    u32 sequence1[4];
    u32 sequence2[4];
    u32 sequence3[4];

    sequence0[0] = sequence_buf0;
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

    test[0] = ctx.h[0] ^ ct_buf[0];
    test[1] = ctx.h[1] ^ ct_buf[1];

    if (sequence_buf0 == 0x01c0)
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

      if (((action == 0x01) || (action == 0x02) || (action == 0x04))
      &&  ((authen_type    >= 0x01) && (authen_type    <= 0x06))
      &&  ((authen_service >= 0x00) && (authen_service <= 0x09))
      &&  ((8 + user_len + port_len + rem_addr_len + data_len) == ct_len))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
    else if ((sequence_buf0 == 0x03c0) || (sequence_buf0 == 0x05c0))
    {
      const u32 msg_len   = ((test[0] >>  0) & 0xff) << 8
                          | ((test[0] >>  8) & 0xff) << 0;
      const u32 data_len  = ((test[0] >> 16) & 0xff) << 8
                          | ((test[0] >> 24) & 0xff) << 0;
      const u32 flags     = ((test[1] >>  0) & 0xff);

      if (((5 + msg_len) == ct_len)
       &&  (data_len == 0)
       &&  (flags == 0))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
    else
    {
      const u32 status    = ((test[0] >>  0) & 0xff);
      const u32 flags     = ((test[0] >>  8) & 0xff);
      const u32 msg_len   = ((test[0] >> 16) & 0xff) << 8
                          | ((test[0] >> 24) & 0xff) << 0;
      const u32 data_len  = ((test[1] >>  0) & 0xff) << 8
                          | ((test[1] >>  8) & 0xff) << 0;

      if (((status >= 0x01 && status <= 0x07) || status == 0x21)
       &&  (flags == 0x01 || flags == 0x00)
       &&  (6 + msg_len + data_len == ct_len))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}
