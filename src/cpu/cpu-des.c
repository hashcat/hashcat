#include <cpu/cpu-des.h>
#include <bit_ops.h>
/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */


u32 BOX(u32 v, u8 i, const u32 S[8][64]);
inline u32 BOX(u32 v, u8 i, const u32 S[8][64]) {
  return S[i][v];
}

void _des_keysetup(u32 data[2], u32 Kc[16], u32 Kd[16], const u32 s_skb[8][64])
{
  u32 c = data[0];
  u32 d = data[1];

  u32 tt;

  PERM_OP(&d, &c, &tt, 4, 0x0f0f0f0f);
  HPERM_OP(&c, &tt, 2, 0xcccc0000);
  HPERM_OP(&d, &tt, 2, 0xcccc0000);
  PERM_OP(&d, &c, &tt, 1, 0x55555555);
  PERM_OP(&c, &d, &tt, 8, 0x00ff00ff);
  PERM_OP(&d, &c, &tt, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) << 0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >> 4);

  c = c & 0x0fffffff;

  int i;

  for (i = 0; i < 16; i++)
  {
    const u32 shifts3s0[16] = { 1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1 };
    const u32 shifts3s1[16] = { 27, 27, 26, 26, 26, 26, 26, 26, 27, 26, 26, 26, 26, 26, 26, 27 };

    c = c >> shifts3s0[i] | c << shifts3s1[i];
    d = d >> shifts3s0[i] | d << shifts3s1[i];

    c = c & 0x0fffffff;
    d = d & 0x0fffffff;

    u32 s = BOX(((c >> 0) & 0x3f), 0, s_skb)
      | BOX((((c >> 6) & 0x03)
        | ((c >> 7) & 0x3c)), 1, s_skb)
      | BOX((((c >> 13) & 0x0f)
        | ((c >> 14) & 0x30)), 2, s_skb)
      | BOX((((c >> 20) & 0x01)
        | ((c >> 21) & 0x06)
        | ((c >> 22) & 0x38)), 3, s_skb);

    u32 s = BOX(((c >> 0) & 0x3f), 0, s_skb)
      | BOX((((c >> 6) & 0x03)
        | ((c >> 7) & 0x3c)), 1, s_skb)
      | BOX((((c >> 13) & 0x0f)
        | ((c >> 14) & 0x30)), 2, s_skb)
      | BOX((((c >> 20) & 0x01)
        | ((c >> 21) & 0x06)
        | ((c >> 22) & 0x38)), 3, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = rotl32(Kc[i], 2u);
    Kd[i] = rotl32(Kd[i], 2u);
  }
}

void _des_encrypt(u32 data[2], u32 Kc[16], u32 Kd[16], const u32 s_SPtrans[8][64])
{
  u32 r = data[0];
  u32 l = data[1];

  u32 tt;

  IP(&r, &l, &tt);

  r = rotl32(r, 3u);
  l = rotl32(l, 3u);

  int i;

  for (i = 0; i < 16; i++)
  {
    u32 u = Kc[i] ^ r;
    u32 t = Kd[i] ^ rotl32(r, 28u);

    l ^= BOX(((u >> 2) & 0x3f), 0, s_SPtrans)
      | BOX(((u >> 10) & 0x3f), 2, s_SPtrans)
      | BOX(((u >> 18) & 0x3f), 4, s_SPtrans)
      | BOX(((u >> 26) & 0x3f), 6, s_SPtrans)
      | BOX(((t >> 2) & 0x3f), 1, s_SPtrans)
      | BOX(((t >> 10) & 0x3f), 3, s_SPtrans)
      | BOX(((t >> 18) & 0x3f), 5, s_SPtrans)
      | BOX(((t >> 26) & 0x3f), 7, s_SPtrans);

    tt = l;
    l = r;
    r = tt;
  }

  l = rotl32(l, 29u);
  r = rotl32(r, 29u);

  FP(&r, &l, &tt);

  data[0] = l;
  data[1] = r;
}

