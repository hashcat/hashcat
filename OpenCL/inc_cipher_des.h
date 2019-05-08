/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_CIPHER_DES_H
#define _INC_CIPHER_DES_H

// these really should be turned into real function
#define PERM_OP(a,b,n,m) \
{                        \
  u32x t;                \
  t = a >> n;            \
  t = t ^ b;             \
  t = t & m;             \
  b = b ^ t;             \
  t = t << n;            \
  a = a ^ t;             \
}

#define HPERM_OP(a,n,m)  \
{                        \
  u32x t;                \
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

#define PERM_OP_S(a,b,n,m) \
{                          \
  u32 t;                   \
  t = a >> n;              \
  t = t ^ b;               \
  t = t & m;               \
  b = b ^ t;               \
  t = t << n;              \
  a = a ^ t;               \
}

#define HPERM_OP_S(a,n,m)  \
{                          \
  u32 t;                   \
  t = a << (16 + n);       \
  t = t ^ a;               \
  t = t & m;               \
  a  = a ^ t;              \
  t = t >> (16 + n);       \
  a  = a ^ t;              \
}

#define DES_IP_S(l,r)                \
{                                    \
  PERM_OP_S (r, l,  4, 0x0f0f0f0f);  \
  PERM_OP_S (l, r, 16, 0x0000ffff);  \
  PERM_OP_S (r, l,  2, 0x33333333);  \
  PERM_OP_S (l, r,  8, 0x00ff00ff);  \
  PERM_OP_S (r, l,  1, 0x55555555);  \
}

#define DES_FP_S(l,r)                \
{                                    \
  PERM_OP_S (l, r,  1, 0x55555555);  \
  PERM_OP_S (r, l,  8, 0x00ff00ff);  \
  PERM_OP_S (l, r,  2, 0x33333333);  \
  PERM_OP_S (r, l, 16, 0x0000ffff);  \
  PERM_OP_S (l, r,  4, 0x0f0f0f0f);  \
}

#define DES_BOX_S(i,n,S) (S)[(n)][(i)]

#if   VECT_SIZE == 1
#define DES_BOX(i,n,S) (S)[(n)][(i)]
#elif VECT_SIZE == 2
#define DES_BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1])
#elif VECT_SIZE == 4
#define DES_BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3])
#elif VECT_SIZE == 8
#define DES_BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7])
#elif VECT_SIZE == 16
#define DES_BOX(i,n,S) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7], (S)[(n)][(i).s8], (S)[(n)][(i).s9], (S)[(n)][(i).sa], (S)[(n)][(i).sb], (S)[(n)][(i).sc], (S)[(n)][(i).sd], (S)[(n)][(i).se], (S)[(n)][(i).sf])
#endif

DECLSPEC void _des_crypt_encrypt (u32 *out, const u32 *in, const u32 *Kc, const u32 *Kd, SHM_TYPE u32 (*s_SPtrans)[64]);
DECLSPEC void _des_crypt_decrypt (u32 *out, const u32 *in, const u32 *Kc, const u32 *Kd, SHM_TYPE u32 (*s_SPtrans)[64]);
DECLSPEC void _des_crypt_keysetup (u32 c, u32 d, u32 *Kc, u32 *Kd, SHM_TYPE u32 (*s_skb)[64]);

DECLSPEC void _des_crypt_encrypt_vect (u32x *out, const u32x *in, const u32x *Kc, const u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64]);
DECLSPEC void _des_crypt_decrypt_vect (u32x *out, const u32x *in, const u32x *Kc, const u32x *Kd, SHM_TYPE u32 (*s_SPtrans)[64]);
DECLSPEC void _des_crypt_keysetup_vect (u32x c, u32x d, u32x *Kc, u32x *Kd, SHM_TYPE u32 (*s_skb)[64]);

#endif // _INC_CIPHER_DES_H
