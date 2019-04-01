/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_cipher_des.h"

DECLSPEC void _des_crypt_encrypt (u32 *out, const u32 *in, const u32 *Kc, const u32 *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32 r = in[0];
  u32 l = in[1];

  DES_IP_S (r, l);

  r = hc_rotl32_S (r, 3u);
  l = hc_rotl32_S (l, 3u);

  for (u32 i = 0; i < 16; i += 2)
  {
    u32 u;
    u32 t;

    u = Kc[i + 0] ^ r;
    t = Kd[i + 0] ^ hc_rotl32_S (r, 28u);

    l ^= DES_BOX_S (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX_S (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX_S (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX_S (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX_S (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX_S (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX_S (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX_S (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i + 1] ^ l;
    t = Kd[i + 1] ^ hc_rotl32_S (l, 28u);

    r ^= DES_BOX_S (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX_S (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX_S (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX_S (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX_S (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX_S (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX_S (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX_S (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = hc_rotl32_S (l, 29u);
  r = hc_rotl32_S (r, 29u);

  DES_FP_S (r, l);

  out[0] = l;
  out[1] = r;
}

DECLSPEC void _des_crypt_decrypt (u32 *out, const u32 *in, const u32 *Kc, const u32 *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32 r = in[0];
  u32 l = in[1];

  DES_IP_S (r, l);

  r = hc_rotl32_S (r, 3u);
  l = hc_rotl32_S (l, 3u);

  for (u32 i = 16; i > 0; i -= 2)
  {
    u32 u;
    u32 t;

    u = Kc[i - 1] ^ r;
    t = Kd[i - 1] ^ hc_rotl32_S (r, 28u);

    l ^= DES_BOX_S (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX_S (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX_S (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX_S (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX_S (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX_S (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX_S (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX_S (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i - 2] ^ l;
    t = Kd[i - 2] ^ hc_rotl32_S (l, 28u);

    r ^= DES_BOX_S (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX_S (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX_S (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX_S (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX_S (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX_S (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX_S (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX_S (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = hc_rotl32_S (l, 29u);
  r = hc_rotl32_S (r, 29u);

  DES_FP_S (r, l);

  out[0] = l;
  out[1] = r;
}

DECLSPEC void _des_crypt_keysetup (u32 c, u32 d, u32 *Kc, u32 *Kd, SHM_TYPE u32 (*s_skb)[64])
{
  PERM_OP_S  (d, c, 4, 0x0f0f0f0f);
  HPERM_OP_S (c,    2, 0xcccc0000);
  HPERM_OP_S (d,    2, 0xcccc0000);
  PERM_OP_S  (d, c, 1, 0x55555555);
  PERM_OP_S  (c, d, 8, 0x00ff00ff);
  PERM_OP_S  (d, c, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) <<  0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >>  4);

  c = c & 0x0fffffff;

  for (u32 i = 0; i < 16; i++)
  {
    if ((i < 2) || (i == 8) || (i == 15))
    {
      c = ((c >> 1) | (c << 27));
      d = ((d >> 1) | (d << 27));
    }
    else
    {
      c = ((c >> 2) | (c << 26));
      d = ((d >> 2) | (d << 26));
    }

    c = c & 0x0fffffff;
    d = d & 0x0fffffff;

    const u32 c00 = (c >>  0) & 0x0000003f;
    const u32 c06 = (c >>  6) & 0x00383003;
    const u32 c07 = (c >>  7) & 0x0000003c;
    const u32 c13 = (c >> 13) & 0x0000060f;
    const u32 c20 = (c >> 20) & 0x00000001;

    u32 s  = DES_BOX_S (((c00 >>  0) & 0xff), 0, s_skb)
           | DES_BOX_S (((c06 >>  0) & 0xff)
                     |((c07 >>  0) & 0xff), 1, s_skb)
           | DES_BOX_S (((c13 >>  0) & 0xff)
                     |((c06 >>  8) & 0xff), 2, s_skb)
           | DES_BOX_S (((c20 >>  0) & 0xff)
                     |((c13 >>  8) & 0xff)
                     |((c06 >> 16) & 0xff), 3, s_skb);

    const u32 d00 = (d >>  0) & 0x00003c3f;
    const u32 d07 = (d >>  7) & 0x00003f03;
    const u32 d21 = (d >> 21) & 0x0000000f;
    const u32 d22 = (d >> 22) & 0x00000030;

    u32 t  = DES_BOX_S (((d00 >>  0) & 0xff), 4, s_skb)
           | DES_BOX_S (((d07 >>  0) & 0xff)
                     |((d00 >>  8) & 0xff), 5, s_skb)
           | DES_BOX_S (((d07 >>  8) & 0xff), 6, s_skb)
           | DES_BOX_S (((d21 >>  0) & 0xff)
                     |((d22 >>  0) & 0xff), 7, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = hc_rotl32_S (Kc[i], 2u);
    Kd[i] = hc_rotl32_S (Kd[i], 2u);
  }
}

DECLSPEC void _des_crypt_encrypt_vect (u32x *out, const u32x *in, const u32x *Kc, const u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32x r = in[0];
  u32x l = in[1];

  DES_IP (r, l);

  r = hc_rotl32 (r, 3u);
  l = hc_rotl32 (l, 3u);

  for (u32 i = 0; i < 16; i += 2)
  {
    u32x u;
    u32x t;

    u = Kc[i + 0] ^ r;
    t = Kd[i + 0] ^ hc_rotl32 (r, 28u);

    l ^= DES_BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i + 1] ^ l;
    t = Kd[i + 1] ^ hc_rotl32 (l, 28u);

    r ^= DES_BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = hc_rotl32 (l, 29u);
  r = hc_rotl32 (r, 29u);

  DES_FP (r, l);

  out[0] = l;
  out[1] = r;
}

DECLSPEC void _des_crypt_decrypt_vect (u32x *out, const u32x *in, const u32x *Kc, const u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32x r = in[0];
  u32x l = in[1];

  DES_IP (r, l);

  r = hc_rotl32 (r, 3u);
  l = hc_rotl32 (l, 3u);

  for (u32 i = 16; i > 0; i -= 2)
  {
    u32x u;
    u32x t;

    u = Kc[i - 1] ^ r;
    t = Kd[i - 1] ^ hc_rotl32 (r, 28u);

    l ^= DES_BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i - 2] ^ l;
    t = Kd[i - 2] ^ hc_rotl32 (l, 28u);

    r ^= DES_BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | DES_BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | DES_BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | DES_BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | DES_BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | DES_BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | DES_BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | DES_BOX (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = hc_rotl32 (l, 29u);
  r = hc_rotl32 (r, 29u);

  DES_FP (r, l);

  out[0] = l;
  out[1] = r;
}

DECLSPEC void _des_crypt_keysetup_vect (u32x c, u32x d, u32x *Kc, u32x *Kd, SHM_TYPE u32 (*s_skb)[64])
{
  PERM_OP  (d, c, 4, 0x0f0f0f0f);
  HPERM_OP (c,    2, 0xcccc0000);
  HPERM_OP (d,    2, 0xcccc0000);
  PERM_OP  (d, c, 1, 0x55555555);
  PERM_OP  (c, d, 8, 0x00ff00ff);
  PERM_OP  (d, c, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) <<  0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >>  4);

  c = c & 0x0fffffff;

  for (u32 i = 0; i < 16; i++)
  {
    if ((i < 2) || (i == 8) || (i == 15))
    {
      c = ((c >> 1) | (c << 27));
      d = ((d >> 1) | (d << 27));
    }
    else
    {
      c = ((c >> 2) | (c << 26));
      d = ((d >> 2) | (d << 26));
    }

    c = c & 0x0fffffff;
    d = d & 0x0fffffff;

    const u32x c00 = (c >>  0) & 0x0000003f;
    const u32x c06 = (c >>  6) & 0x00383003;
    const u32x c07 = (c >>  7) & 0x0000003c;
    const u32x c13 = (c >> 13) & 0x0000060f;
    const u32x c20 = (c >> 20) & 0x00000001;

    u32x s = DES_BOX (((c00 >>  0) & 0xff), 0, s_skb)
           | DES_BOX (((c06 >>  0) & 0xff)
                     |((c07 >>  0) & 0xff), 1, s_skb)
           | DES_BOX (((c13 >>  0) & 0xff)
                     |((c06 >>  8) & 0xff), 2, s_skb)
           | DES_BOX (((c20 >>  0) & 0xff)
                     |((c13 >>  8) & 0xff)
                     |((c06 >> 16) & 0xff), 3, s_skb);

    const u32x d00 = (d >>  0) & 0x00003c3f;
    const u32x d07 = (d >>  7) & 0x00003f03;
    const u32x d21 = (d >> 21) & 0x0000000f;
    const u32x d22 = (d >> 22) & 0x00000030;

    u32x t = DES_BOX (((d00 >>  0) & 0xff), 4, s_skb)
           | DES_BOX (((d07 >>  0) & 0xff)
                     |((d00 >>  8) & 0xff), 5, s_skb)
           | DES_BOX (((d07 >>  8) & 0xff), 6, s_skb)
           | DES_BOX (((d21 >>  0) & 0xff)
                     |((d22 >>  0) & 0xff), 7, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = hc_rotl32 (Kc[i], 2u);
    Kd[i] = hc_rotl32 (Kd[i], 2u);
  }
}
