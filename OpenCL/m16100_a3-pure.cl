/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_md5.cl"

__kernel void m16100_mxx (KERN_ATTR_VECTOR_ESALT (tacacs_plus_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  u32 session0[4];
  u32 session1[4];
  u32 session2[4];
  u32 session3[4];

  session0[0] = esalt_bufs[digests_offset].session_buf[0];
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

  ct_buf[0] = esalt_bufs[digests_offset].ct_data_buf[0];
  ct_buf[1] = esalt_bufs[digests_offset].ct_data_buf[1];

  u32 ct_len = esalt_bufs[digests_offset].ct_data_len;

  u32 sequence_buf0 = esalt_bufs[digests_offset].sequence_buf[0];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_vector_t ctx;

    md5_init_vector_from_scalar (&ctx, &ctx0);

    md5_update_vector (&ctx, w, pw_len);

    u32x sequence0[4];
    u32x sequence1[4];
    u32x sequence2[4];
    u32x sequence3[4];

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

    md5_update_vector_64 (&ctx, sequence0, sequence1, sequence2, sequence3, 2);

    md5_final_vector (&ctx);

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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
        }
      }
    }
  }
}

__kernel void m16100_sxx (KERN_ATTR_VECTOR_ESALT (tacacs_plus_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  u32 session0[4];
  u32 session1[4];
  u32 session2[4];
  u32 session3[4];

  session0[0] = esalt_bufs[digests_offset].session_buf[0];
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

  ct_buf[0] = esalt_bufs[digests_offset].ct_data_buf[0];
  ct_buf[1] = esalt_bufs[digests_offset].ct_data_buf[1];

  u32 ct_len = esalt_bufs[digests_offset].ct_data_len;

  u32 sequence_buf0 = esalt_bufs[digests_offset].sequence_buf[0];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_vector_t ctx;

    md5_init_vector_from_scalar (&ctx, &ctx0);

    md5_update_vector (&ctx, w, pw_len);

    u32x sequence0[4];
    u32x sequence1[4];
    u32x sequence2[4];
    u32x sequence3[4];

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

    md5_update_vector_64 (&ctx, sequence0, sequence1, sequence2, sequence3, 2);

    md5_final_vector (&ctx);

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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
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
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
        }
      }
    }
  }
}
