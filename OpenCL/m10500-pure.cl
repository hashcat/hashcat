/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_hash_md5.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

CONSTANT_VK u32a padding[8] =
{
  0x5e4ebf28,
  0x418a754e,
  0x564e0064,
  0x0801faff,
  0xb6002e2e,
  0x803e68d0,
  0xfea90c2f,
  0x7a695364
};

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

typedef struct pdf14_tmp
{
  u32 digest[4];
  u32 out[4];

} pdf14_tmp_t;

typedef struct
{
  u8 S[256];

  u32 wtf_its_faster;

} RC4_KEY;

DECLSPEC void swap (LOCAL_AS RC4_KEY *rc4_key, const u8 i, const u8 j)
{
  u8 tmp;

  tmp           = rc4_key->S[i];
  rc4_key->S[i] = rc4_key->S[j];
  rc4_key->S[j] = tmp;
}

DECLSPEC void rc4_init_16 (LOCAL_AS RC4_KEY *rc4_key, const u32 *data)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  LOCAL_AS u32 *ptr = (LOCAL_AS u32 *) rc4_key->S;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 64; i++)
  {
    *ptr++ = v; v += a;
  }

  u32 j = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 16; i++)
  {
    u32 idx = i * 16;

    u32 v;

    v = data[0];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[1];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[2];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;

    v = data[3];

    j += rc4_key->S[idx] + (v >>  0); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >>  8); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 16); swap (rc4_key, idx, j); idx++;
    j += rc4_key->S[idx] + (v >> 24); swap (rc4_key, idx, j); idx++;
  }
}

DECLSPEC u8 rc4_next_16 (LOCAL_AS RC4_KEY *rc4_key, u8 i, u8 j, const u32 *in, u32 *out)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u8 idx;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  0;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] <<  8;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 16;

    i += 1;
    j += rc4_key->S[i];

    swap (rc4_key, i, j);

    idx = rc4_key->S[i] + rc4_key->S[j];

    xor4 |= rc4_key->S[idx] << 24;

    out[k] = in[k] ^ xor4;
  }

  return j;
}

KERNEL_FQ void m10500_init (KERN_ATTR_TMPS_ESALT (pdf14_tmp_t, pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  //const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  //LOCAL_AS RC4_KEY rc4_keys[64];
  //LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[digests_offset].o_buf[0];
  o_buf[1] = esalt_bufs[digests_offset].o_buf[1];
  o_buf[2] = esalt_bufs[digests_offset].o_buf[2];
  o_buf[3] = esalt_bufs[digests_offset].o_buf[3];
  o_buf[4] = esalt_bufs[digests_offset].o_buf[4];
  o_buf[5] = esalt_bufs[digests_offset].o_buf[5];
  o_buf[6] = esalt_bufs[digests_offset].o_buf[6];
  o_buf[7] = esalt_bufs[digests_offset].o_buf[7];

  u32 P = esalt_bufs[digests_offset].P;

  u32 id_buf[12];

  id_buf[ 0] = esalt_bufs[digests_offset].id_buf[0];
  id_buf[ 1] = esalt_bufs[digests_offset].id_buf[1];
  id_buf[ 2] = esalt_bufs[digests_offset].id_buf[2];
  id_buf[ 3] = esalt_bufs[digests_offset].id_buf[3];

  id_buf[ 4] = esalt_bufs[digests_offset].id_buf[4];
  id_buf[ 5] = esalt_bufs[digests_offset].id_buf[5];
  id_buf[ 6] = esalt_bufs[digests_offset].id_buf[6];
  id_buf[ 7] = esalt_bufs[digests_offset].id_buf[7];

  id_buf[ 8] = 0;
  id_buf[ 9] = 0;
  id_buf[10] = 0;
  id_buf[11] = 0;

  u32 id_len  = esalt_bufs[digests_offset].id_len;
  u32 id_len4 = id_len / 4;

  u32 rc4data[2];

  rc4data[0] = esalt_bufs[digests_offset].rc4data[0];
  rc4data[1] = esalt_bufs[digests_offset].rc4data[1];

  u32 final_length = 68 + id_len;

  u32 w11 = 0x80;
  u32 w12 = 0;

  if (esalt_bufs[digests_offset].enc_md != 1)
  {
    w11 = 0xffffffff;
    w12 = 0x80;

    final_length += 4;
  }

  id_buf[id_len4 + 0] = w11;
  id_buf[id_len4 + 1] = w12;

  /**
   * main init
   */

  u32 w0_t[4];
  u32 w1_t[4];
  u32 w2_t[4];
  u32 w3_t[4];

  // max length supported by pdf11 is 32

  w0_t[0] = padding[0];
  w0_t[1] = padding[1];
  w0_t[2] = padding[2];
  w0_t[3] = padding[3];
  w1_t[0] = padding[4];
  w1_t[1] = padding[5];
  w1_t[2] = padding[6];
  w1_t[3] = padding[7];
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  switch_buffer_by_offset_le (w0_t, w1_t, w2_t, w3_t, pw_len);

  // add password
  // truncate at 32 is wanted, not a bug!
  // add o_buf

  w0_t[0] |= w0[0];
  w0_t[1] |= w0[1];
  w0_t[2] |= w0[2];
  w0_t[3] |= w0[3];
  w1_t[0] |= w1[0];
  w1_t[1] |= w1[1];
  w1_t[2] |= w1[2];
  w1_t[3] |= w1[3];
  w2_t[0]  = o_buf[0];
  w2_t[1]  = o_buf[1];
  w2_t[2]  = o_buf[2];
  w2_t[3]  = o_buf[3];
  w3_t[0]  = o_buf[4];
  w3_t[1]  = o_buf[5];
  w3_t[2]  = o_buf[6];
  w3_t[3]  = o_buf[7];

  u32 digest[4];

  digest[0] = MD5M_A;
  digest[1] = MD5M_B;
  digest[2] = MD5M_C;
  digest[3] = MD5M_D;

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = P;
  w0_t[1] = id_buf[ 0];
  w0_t[2] = id_buf[ 1];
  w0_t[3] = id_buf[ 2];
  w1_t[0] = id_buf[ 3];
  w1_t[1] = id_buf[ 4];
  w1_t[2] = id_buf[ 5];
  w1_t[3] = id_buf[ 6];
  w2_t[0] = id_buf[ 7];
  w2_t[1] = id_buf[ 8];
  w2_t[2] = id_buf[ 9];
  w2_t[3] = id_buf[10];
  w3_t[0] = id_buf[11];
  w3_t[1] = 0;
  w3_t[2] = final_length * 8;
  w3_t[3] = 0;

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  tmps[gid].digest[0] = digest[0];
  tmps[gid].digest[1] = digest[1];
  tmps[gid].digest[2] = digest[2];
  tmps[gid].digest[3] = digest[3];

  tmps[gid].out[0] = rc4data[0];
  tmps[gid].out[1] = rc4data[1];
  tmps[gid].out[2] = 0;
  tmps[gid].out[3] = 0;
}

KERNEL_FQ void m10500_loop (KERN_ATTR_TMPS_ESALT (pdf14_tmp_t, pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  /**
   * shared
   */

  LOCAL_VK RC4_KEY rc4_keys[64];

  LOCAL_AS RC4_KEY *rc4_key = &rc4_keys[lid];

  /**
   * loop
   */

  u32 digest[4];

  digest[0] = tmps[gid].digest[0];
  digest[1] = tmps[gid].digest[1];
  digest[2] = tmps[gid].digest[2];
  digest[3] = tmps[gid].digest[3];

  u32 out[4];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    if (j < 50)
    {
      u32 w0_t[4];
      u32 w1_t[4];
      u32 w2_t[4];
      u32 w3_t[4];

      w0_t[0] = digest[0];
      w0_t[1] = digest[1];
      w0_t[2] = digest[2];
      w0_t[3] = digest[3];
      w1_t[0] = 0x80;
      w1_t[1] = 0;
      w1_t[2] = 0;
      w1_t[3] = 0;
      w2_t[0] = 0;
      w2_t[1] = 0;
      w2_t[2] = 0;
      w2_t[3] = 0;
      w3_t[0] = 0;
      w3_t[1] = 0;
      w3_t[2] = 16 * 8;
      w3_t[3] = 0;

      digest[0] = MD5M_A;
      digest[1] = MD5M_B;
      digest[2] = MD5M_C;
      digest[3] = MD5M_D;

      md5_transform (w0_t, w1_t, w2_t, w3_t, digest);
    }
    else
    {
      const u32 x = j - 50;

      const u32 xv = x <<  0
                   | x <<  8
                   | x << 16
                   | x << 24;

      u32 tmp[4];

      tmp[0] = digest[0] ^ xv;
      tmp[1] = digest[1] ^ xv;
      tmp[2] = digest[2] ^ xv;
      tmp[3] = digest[3] ^ xv;

      rc4_init_16 (rc4_key, tmp);

      rc4_next_16 (rc4_key, 0, 0, out, out);
    }
  }

  tmps[gid].digest[0] = digest[0];
  tmps[gid].digest[1] = digest[1];
  tmps[gid].digest[2] = digest[2];
  tmps[gid].digest[3] = digest[3];

  tmps[gid].out[0] = out[0];
  tmps[gid].out[1] = out[1];
  tmps[gid].out[2] = out[2];
  tmps[gid].out[3] = out[3];
}

KERNEL_FQ void m10500_comp (KERN_ATTR_TMPS_ESALT (pdf14_tmp_t, pdf_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].out[0];
  const u32 r1 = tmps[gid].out[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
