/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_DES_H
#define _CPU_DES_H

#define PERM_OP(a,b,n,m) \
{                        \
  u32 t;                 \
  t = a >> n;            \
  t = t ^ b;             \
  t = t & m;             \
  b = b ^ t;             \
  t = t << n;            \
  a = a ^ t;             \
}

#define HPERM_OP(a,n,m)  \
{                        \
  u32 t;                 \
  t = a << (16 + n);     \
  t = t ^ a;             \
  t = t & m;             \
  a  = a ^ t;            \
  t = t >> (16 + n);     \
  a  = a ^ t;            \
}

#define DES_IP(l,r)                \
{                                  \
  PERM_OP (r, l,  4, 0x0f0f0f0f);  \
  PERM_OP (l, r, 16, 0x0000ffff);  \
  PERM_OP (r, l,  2, 0x33333333);  \
  PERM_OP (l, r,  8, 0x00ff00ff);  \
  PERM_OP (r, l,  1, 0x55555555);  \
}

#define DES_FP(l,r)                \
{                                  \
  PERM_OP (l, r,  1, 0x55555555);  \
  PERM_OP (r, l,  8, 0x00ff00ff);  \
  PERM_OP (l, r,  2, 0x33333333);  \
  PERM_OP (r, l, 16, 0x0000ffff);  \
  PERM_OP (l, r,  4, 0x0f0f0f0f);  \
}

void _des_keysetup (const u32 data[2], u32 Kc[16], u32 Kd[16]);
void _des_encrypt (u32 data[2], const u32 Kc[16], const u32 Kd[16]);

#endif // _CPU_DES_H
