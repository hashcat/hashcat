/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define PERM_OP(a,b,tt,n,m) \
{                           \
  tt = a >> n;              \
  tt = tt ^ b;              \
  tt = tt & m;              \
  b = b ^ tt;               \
  tt = tt << n;             \
  a = a ^ tt;               \
}

#define HPERM_OP(a,tt,n,m)  \
{                           \
  tt = a << (16 + n);       \
  tt = tt ^ a;              \
  tt = tt & m;              \
  a  = a ^ tt;              \
  tt = tt >> (16 + n);      \
  a  = a ^ tt;              \
}

#define IP(l,r,tt)                     \
{                                      \
  PERM_OP (r, l, tt,  4, 0x0f0f0f0f);  \
  PERM_OP (l, r, tt, 16, 0x0000ffff);  \
  PERM_OP (r, l, tt,  2, 0x33333333);  \
  PERM_OP (l, r, tt,  8, 0x00ff00ff);  \
  PERM_OP (r, l, tt,  1, 0x55555555);  \
}

#define FP(l,r,tt)                     \
{                                      \
  PERM_OP (l, r, tt,  1, 0x55555555);  \
  PERM_OP (r, l, tt,  8, 0x00ff00ff);  \
  PERM_OP (l, r, tt,  2, 0x33333333);  \
  PERM_OP (r, l, tt, 16, 0x0000ffff);  \
  PERM_OP (l, r, tt,  4, 0x0f0f0f0f);  \
}

__constant u32a c_SPtrans[8][64] =
{
  {
    /* nibble 0 */
    0x02080800, 0x00080000, 0x02000002, 0x02080802,
    0x02000000, 0x00080802, 0x00080002, 0x02000002,
    0x00080802, 0x02080800, 0x02080000, 0x00000802,
    0x02000802, 0x02000000, 0x00000000, 0x00080002,
    0x00080000, 0x00000002, 0x02000800, 0x00080800,
    0x02080802, 0x02080000, 0x00000802, 0x02000800,
    0x00000002, 0x00000800, 0x00080800, 0x02080002,
    0x00000800, 0x02000802, 0x02080002, 0x00000000,
    0x00000000, 0x02080802, 0x02000800, 0x00080002,
    0x02080800, 0x00080000, 0x00000802, 0x02000800,
    0x02080002, 0x00000800, 0x00080800, 0x02000002,
    0x00080802, 0x00000002, 0x02000002, 0x02080000,
    0x02080802, 0x00080800, 0x02080000, 0x02000802,
    0x02000000, 0x00000802, 0x00080002, 0x00000000,
    0x00080000, 0x02000000, 0x02000802, 0x02080800,
    0x00000002, 0x02080002, 0x00000800, 0x00080802,
  },
  {
    /* nibble 1 */
    0x40108010, 0x00000000, 0x00108000, 0x40100000,
    0x40000010, 0x00008010, 0x40008000, 0x00108000,
    0x00008000, 0x40100010, 0x00000010, 0x40008000,
    0x00100010, 0x40108000, 0x40100000, 0x00000010,
    0x00100000, 0x40008010, 0x40100010, 0x00008000,
    0x00108010, 0x40000000, 0x00000000, 0x00100010,
    0x40008010, 0x00108010, 0x40108000, 0x40000010,
    0x40000000, 0x00100000, 0x00008010, 0x40108010,
    0x00100010, 0x40108000, 0x40008000, 0x00108010,
    0x40108010, 0x00100010, 0x40000010, 0x00000000,
    0x40000000, 0x00008010, 0x00100000, 0x40100010,
    0x00008000, 0x40000000, 0x00108010, 0x40008010,
    0x40108000, 0x00008000, 0x00000000, 0x40000010,
    0x00000010, 0x40108010, 0x00108000, 0x40100000,
    0x40100010, 0x00100000, 0x00008010, 0x40008000,
    0x40008010, 0x00000010, 0x40100000, 0x00108000,
  },
  {
    /* nibble 2 */
    0x04000001, 0x04040100, 0x00000100, 0x04000101,
    0x00040001, 0x04000000, 0x04000101, 0x00040100,
    0x04000100, 0x00040000, 0x04040000, 0x00000001,
    0x04040101, 0x00000101, 0x00000001, 0x04040001,
    0x00000000, 0x00040001, 0x04040100, 0x00000100,
    0x00000101, 0x04040101, 0x00040000, 0x04000001,
    0x04040001, 0x04000100, 0x00040101, 0x04040000,
    0x00040100, 0x00000000, 0x04000000, 0x00040101,
    0x04040100, 0x00000100, 0x00000001, 0x00040000,
    0x00000101, 0x00040001, 0x04040000, 0x04000101,
    0x00000000, 0x04040100, 0x00040100, 0x04040001,
    0x00040001, 0x04000000, 0x04040101, 0x00000001,
    0x00040101, 0x04000001, 0x04000000, 0x04040101,
    0x00040000, 0x04000100, 0x04000101, 0x00040100,
    0x04000100, 0x00000000, 0x04040001, 0x00000101,
    0x04000001, 0x00040101, 0x00000100, 0x04040000,
  },
  {
    /* nibble 3 */
    0x00401008, 0x10001000, 0x00000008, 0x10401008,
    0x00000000, 0x10400000, 0x10001008, 0x00400008,
    0x10401000, 0x10000008, 0x10000000, 0x00001008,
    0x10000008, 0x00401008, 0x00400000, 0x10000000,
    0x10400008, 0x00401000, 0x00001000, 0x00000008,
    0x00401000, 0x10001008, 0x10400000, 0x00001000,
    0x00001008, 0x00000000, 0x00400008, 0x10401000,
    0x10001000, 0x10400008, 0x10401008, 0x00400000,
    0x10400008, 0x00001008, 0x00400000, 0x10000008,
    0x00401000, 0x10001000, 0x00000008, 0x10400000,
    0x10001008, 0x00000000, 0x00001000, 0x00400008,
    0x00000000, 0x10400008, 0x10401000, 0x00001000,
    0x10000000, 0x10401008, 0x00401008, 0x00400000,
    0x10401008, 0x00000008, 0x10001000, 0x00401008,
    0x00400008, 0x00401000, 0x10400000, 0x10001008,
    0x00001008, 0x10000000, 0x10000008, 0x10401000,
  },
  {
    /* nibble 4 */
    0x08000000, 0x00010000, 0x00000400, 0x08010420,
    0x08010020, 0x08000400, 0x00010420, 0x08010000,
    0x00010000, 0x00000020, 0x08000020, 0x00010400,
    0x08000420, 0x08010020, 0x08010400, 0x00000000,
    0x00010400, 0x08000000, 0x00010020, 0x00000420,
    0x08000400, 0x00010420, 0x00000000, 0x08000020,
    0x00000020, 0x08000420, 0x08010420, 0x00010020,
    0x08010000, 0x00000400, 0x00000420, 0x08010400,
    0x08010400, 0x08000420, 0x00010020, 0x08010000,
    0x00010000, 0x00000020, 0x08000020, 0x08000400,
    0x08000000, 0x00010400, 0x08010420, 0x00000000,
    0x00010420, 0x08000000, 0x00000400, 0x00010020,
    0x08000420, 0x00000400, 0x00000000, 0x08010420,
    0x08010020, 0x08010400, 0x00000420, 0x00010000,
    0x00010400, 0x08010020, 0x08000400, 0x00000420,
    0x00000020, 0x00010420, 0x08010000, 0x08000020,
  },
  {
    /* nibble 5 */
    0x80000040, 0x00200040, 0x00000000, 0x80202000,
    0x00200040, 0x00002000, 0x80002040, 0x00200000,
    0x00002040, 0x80202040, 0x00202000, 0x80000000,
    0x80002000, 0x80000040, 0x80200000, 0x00202040,
    0x00200000, 0x80002040, 0x80200040, 0x00000000,
    0x00002000, 0x00000040, 0x80202000, 0x80200040,
    0x80202040, 0x80200000, 0x80000000, 0x00002040,
    0x00000040, 0x00202000, 0x00202040, 0x80002000,
    0x00002040, 0x80000000, 0x80002000, 0x00202040,
    0x80202000, 0x00200040, 0x00000000, 0x80002000,
    0x80000000, 0x00002000, 0x80200040, 0x00200000,
    0x00200040, 0x80202040, 0x00202000, 0x00000040,
    0x80202040, 0x00202000, 0x00200000, 0x80002040,
    0x80000040, 0x80200000, 0x00202040, 0x00000000,
    0x00002000, 0x80000040, 0x80002040, 0x80202000,
    0x80200000, 0x00002040, 0x00000040, 0x80200040,
  },
  {
    /* nibble 6 */
    0x00004000, 0x00000200, 0x01000200, 0x01000004,
    0x01004204, 0x00004004, 0x00004200, 0x00000000,
    0x01000000, 0x01000204, 0x00000204, 0x01004000,
    0x00000004, 0x01004200, 0x01004000, 0x00000204,
    0x01000204, 0x00004000, 0x00004004, 0x01004204,
    0x00000000, 0x01000200, 0x01000004, 0x00004200,
    0x01004004, 0x00004204, 0x01004200, 0x00000004,
    0x00004204, 0x01004004, 0x00000200, 0x01000000,
    0x00004204, 0x01004000, 0x01004004, 0x00000204,
    0x00004000, 0x00000200, 0x01000000, 0x01004004,
    0x01000204, 0x00004204, 0x00004200, 0x00000000,
    0x00000200, 0x01000004, 0x00000004, 0x01000200,
    0x00000000, 0x01000204, 0x01000200, 0x00004200,
    0x00000204, 0x00004000, 0x01004204, 0x01000000,
    0x01004200, 0x00000004, 0x00004004, 0x01004204,
    0x01000004, 0x01004200, 0x01004000, 0x00004004,
  },
  {
    /* nibble 7 */
    0x20800080, 0x20820000, 0x00020080, 0x00000000,
    0x20020000, 0x00800080, 0x20800000, 0x20820080,
    0x00000080, 0x20000000, 0x00820000, 0x00020080,
    0x00820080, 0x20020080, 0x20000080, 0x20800000,
    0x00020000, 0x00820080, 0x00800080, 0x20020000,
    0x20820080, 0x20000080, 0x00000000, 0x00820000,
    0x20000000, 0x00800000, 0x20020080, 0x20800080,
    0x00800000, 0x00020000, 0x20820000, 0x00000080,
    0x00800000, 0x00020000, 0x20000080, 0x20820080,
    0x00020080, 0x20000000, 0x00000000, 0x00820000,
    0x20800080, 0x20020080, 0x20020000, 0x00800080,
    0x20820000, 0x00000080, 0x00800080, 0x20020000,
    0x20820080, 0x00800000, 0x20800000, 0x20000080,
    0x00820000, 0x00020080, 0x20020080, 0x20800000,
    0x00000080, 0x20820000, 0x00820080, 0x00000000,
    0x20000000, 0x20800080, 0x00020000, 0x00820080,
  },
};

__constant u32a c_skb[8][64] =
{
  {
    0x00000000, 0x00000010, 0x20000000, 0x20000010,
    0x00010000, 0x00010010, 0x20010000, 0x20010010,
    0x00000800, 0x00000810, 0x20000800, 0x20000810,
    0x00010800, 0x00010810, 0x20010800, 0x20010810,
    0x00000020, 0x00000030, 0x20000020, 0x20000030,
    0x00010020, 0x00010030, 0x20010020, 0x20010030,
    0x00000820, 0x00000830, 0x20000820, 0x20000830,
    0x00010820, 0x00010830, 0x20010820, 0x20010830,
    0x00080000, 0x00080010, 0x20080000, 0x20080010,
    0x00090000, 0x00090010, 0x20090000, 0x20090010,
    0x00080800, 0x00080810, 0x20080800, 0x20080810,
    0x00090800, 0x00090810, 0x20090800, 0x20090810,
    0x00080020, 0x00080030, 0x20080020, 0x20080030,
    0x00090020, 0x00090030, 0x20090020, 0x20090030,
    0x00080820, 0x00080830, 0x20080820, 0x20080830,
    0x00090820, 0x00090830, 0x20090820, 0x20090830,
  },
  {
    0x00000000, 0x02000000, 0x00002000, 0x02002000,
    0x00200000, 0x02200000, 0x00202000, 0x02202000,
    0x00000004, 0x02000004, 0x00002004, 0x02002004,
    0x00200004, 0x02200004, 0x00202004, 0x02202004,
    0x00000400, 0x02000400, 0x00002400, 0x02002400,
    0x00200400, 0x02200400, 0x00202400, 0x02202400,
    0x00000404, 0x02000404, 0x00002404, 0x02002404,
    0x00200404, 0x02200404, 0x00202404, 0x02202404,
    0x10000000, 0x12000000, 0x10002000, 0x12002000,
    0x10200000, 0x12200000, 0x10202000, 0x12202000,
    0x10000004, 0x12000004, 0x10002004, 0x12002004,
    0x10200004, 0x12200004, 0x10202004, 0x12202004,
    0x10000400, 0x12000400, 0x10002400, 0x12002400,
    0x10200400, 0x12200400, 0x10202400, 0x12202400,
    0x10000404, 0x12000404, 0x10002404, 0x12002404,
    0x10200404, 0x12200404, 0x10202404, 0x12202404,
  },
  {
    0x00000000, 0x00000001, 0x00040000, 0x00040001,
    0x01000000, 0x01000001, 0x01040000, 0x01040001,
    0x00000002, 0x00000003, 0x00040002, 0x00040003,
    0x01000002, 0x01000003, 0x01040002, 0x01040003,
    0x00000200, 0x00000201, 0x00040200, 0x00040201,
    0x01000200, 0x01000201, 0x01040200, 0x01040201,
    0x00000202, 0x00000203, 0x00040202, 0x00040203,
    0x01000202, 0x01000203, 0x01040202, 0x01040203,
    0x08000000, 0x08000001, 0x08040000, 0x08040001,
    0x09000000, 0x09000001, 0x09040000, 0x09040001,
    0x08000002, 0x08000003, 0x08040002, 0x08040003,
    0x09000002, 0x09000003, 0x09040002, 0x09040003,
    0x08000200, 0x08000201, 0x08040200, 0x08040201,
    0x09000200, 0x09000201, 0x09040200, 0x09040201,
    0x08000202, 0x08000203, 0x08040202, 0x08040203,
    0x09000202, 0x09000203, 0x09040202, 0x09040203,
  },
  {
    0x00000000, 0x00100000, 0x00000100, 0x00100100,
    0x00000008, 0x00100008, 0x00000108, 0x00100108,
    0x00001000, 0x00101000, 0x00001100, 0x00101100,
    0x00001008, 0x00101008, 0x00001108, 0x00101108,
    0x04000000, 0x04100000, 0x04000100, 0x04100100,
    0x04000008, 0x04100008, 0x04000108, 0x04100108,
    0x04001000, 0x04101000, 0x04001100, 0x04101100,
    0x04001008, 0x04101008, 0x04001108, 0x04101108,
    0x00020000, 0x00120000, 0x00020100, 0x00120100,
    0x00020008, 0x00120008, 0x00020108, 0x00120108,
    0x00021000, 0x00121000, 0x00021100, 0x00121100,
    0x00021008, 0x00121008, 0x00021108, 0x00121108,
    0x04020000, 0x04120000, 0x04020100, 0x04120100,
    0x04020008, 0x04120008, 0x04020108, 0x04120108,
    0x04021000, 0x04121000, 0x04021100, 0x04121100,
    0x04021008, 0x04121008, 0x04021108, 0x04121108,
  },
  {
    0x00000000, 0x10000000, 0x00010000, 0x10010000,
    0x00000004, 0x10000004, 0x00010004, 0x10010004,
    0x20000000, 0x30000000, 0x20010000, 0x30010000,
    0x20000004, 0x30000004, 0x20010004, 0x30010004,
    0x00100000, 0x10100000, 0x00110000, 0x10110000,
    0x00100004, 0x10100004, 0x00110004, 0x10110004,
    0x20100000, 0x30100000, 0x20110000, 0x30110000,
    0x20100004, 0x30100004, 0x20110004, 0x30110004,
    0x00001000, 0x10001000, 0x00011000, 0x10011000,
    0x00001004, 0x10001004, 0x00011004, 0x10011004,
    0x20001000, 0x30001000, 0x20011000, 0x30011000,
    0x20001004, 0x30001004, 0x20011004, 0x30011004,
    0x00101000, 0x10101000, 0x00111000, 0x10111000,
    0x00101004, 0x10101004, 0x00111004, 0x10111004,
    0x20101000, 0x30101000, 0x20111000, 0x30111000,
    0x20101004, 0x30101004, 0x20111004, 0x30111004,
  },
  {
    0x00000000, 0x08000000, 0x00000008, 0x08000008,
    0x00000400, 0x08000400, 0x00000408, 0x08000408,
    0x00020000, 0x08020000, 0x00020008, 0x08020008,
    0x00020400, 0x08020400, 0x00020408, 0x08020408,
    0x00000001, 0x08000001, 0x00000009, 0x08000009,
    0x00000401, 0x08000401, 0x00000409, 0x08000409,
    0x00020001, 0x08020001, 0x00020009, 0x08020009,
    0x00020401, 0x08020401, 0x00020409, 0x08020409,
    0x02000000, 0x0A000000, 0x02000008, 0x0A000008,
    0x02000400, 0x0A000400, 0x02000408, 0x0A000408,
    0x02020000, 0x0A020000, 0x02020008, 0x0A020008,
    0x02020400, 0x0A020400, 0x02020408, 0x0A020408,
    0x02000001, 0x0A000001, 0x02000009, 0x0A000009,
    0x02000401, 0x0A000401, 0x02000409, 0x0A000409,
    0x02020001, 0x0A020001, 0x02020009, 0x0A020009,
    0x02020401, 0x0A020401, 0x02020409, 0x0A020409,
  },
  {
    0x00000000, 0x00000100, 0x00080000, 0x00080100,
    0x01000000, 0x01000100, 0x01080000, 0x01080100,
    0x00000010, 0x00000110, 0x00080010, 0x00080110,
    0x01000010, 0x01000110, 0x01080010, 0x01080110,
    0x00200000, 0x00200100, 0x00280000, 0x00280100,
    0x01200000, 0x01200100, 0x01280000, 0x01280100,
    0x00200010, 0x00200110, 0x00280010, 0x00280110,
    0x01200010, 0x01200110, 0x01280010, 0x01280110,
    0x00000200, 0x00000300, 0x00080200, 0x00080300,
    0x01000200, 0x01000300, 0x01080200, 0x01080300,
    0x00000210, 0x00000310, 0x00080210, 0x00080310,
    0x01000210, 0x01000310, 0x01080210, 0x01080310,
    0x00200200, 0x00200300, 0x00280200, 0x00280300,
    0x01200200, 0x01200300, 0x01280200, 0x01280300,
    0x00200210, 0x00200310, 0x00280210, 0x00280310,
    0x01200210, 0x01200310, 0x01280210, 0x01280310,
  },
  {
    0x00000000, 0x04000000, 0x00040000, 0x04040000,
    0x00000002, 0x04000002, 0x00040002, 0x04040002,
    0x00002000, 0x04002000, 0x00042000, 0x04042000,
    0x00002002, 0x04002002, 0x00042002, 0x04042002,
    0x00000020, 0x04000020, 0x00040020, 0x04040020,
    0x00000022, 0x04000022, 0x00040022, 0x04040022,
    0x00002020, 0x04002020, 0x00042020, 0x04042020,
    0x00002022, 0x04002022, 0x00042022, 0x04042022,
    0x00000800, 0x04000800, 0x00040800, 0x04040800,
    0x00000802, 0x04000802, 0x00040802, 0x04040802,
    0x00002800, 0x04002800, 0x00042800, 0x04042800,
    0x00002802, 0x04002802, 0x00042802, 0x04042802,
    0x00000820, 0x04000820, 0x00040820, 0x04040820,
    0x00000822, 0x04000822, 0x00040822, 0x04040822,
    0x00002820, 0x04002820, 0x00042820, 0x04042820,
    0x00002822, 0x04002822, 0x00042822, 0x04042822
  }
};

#define BOX(i,n,S) (S)[(n)][(i)]
#define BOX1(i,S) (S)[(i)]

void _des_crypt_encrypt (u32 iv[2], u32 data[2], u32 Kc[16], u32 Kd[16], __local u32 (*s_SPtrans)[64])
{
  u32 tt;

  u32 r = data[0];
  u32 l = data[1];

  IP (r, l, tt);

  r = rotl32_S (r, 3u);
  l = rotl32_S (l, 3u);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 16; i += 2)
  {
    u32 u;
    u32 t;

    u = Kc[i + 0] ^ r;
    t = Kd[i + 0] ^ rotl32_S (r, 28u);

    l ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i + 1] ^ l;
    t = Kd[i + 1] ^ rotl32_S (l, 28u);

    r ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = rotl32_S (l, 29u);
  r = rotl32_S (r, 29u);

  FP (r, l, tt);

  iv[0] = l;
  iv[1] = r;
}

void _des_crypt_decrypt (u32 iv[2], u32 data[2], u32 Kc[16], u32 Kd[16], __local u32 (*s_SPtrans)[64])
{
  u32 tt;

  u32 r = data[0];
  u32 l = data[1];

  IP (r, l, tt);

  r = rotl32_S (r, 3u);
  l = rotl32_S (l, 3u);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 16; i > 0; i -= 2)
  {
    u32 u;
    u32 t;

    u = Kc[i - 1] ^ r;
    t = Kd[i - 1] ^ rotl32_S (r, 28u);

    l ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    u = Kc[i - 2] ^ l;
    t = Kd[i - 2] ^ rotl32_S (l, 28u);

    r ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);
  }

  l = rotl32_S (l, 29u);
  r = rotl32_S (r, 29u);

  FP (r, l, tt);

  iv[0] = l;
  iv[1] = r;
}

void _des_crypt_keysetup (u32 c, u32 d, u32 Kc[16], u32 Kd[16], __local u32 (*s_skb)[64])
{
  u32 tt;

  PERM_OP  (d, c, tt, 4, 0x0f0f0f0f);
  HPERM_OP (c,    tt, 2, 0xcccc0000);
  HPERM_OP (d,    tt, 2, 0xcccc0000);
  PERM_OP  (d, c, tt, 1, 0x55555555);
  PERM_OP  (c, d, tt, 8, 0x00ff00ff);
  PERM_OP  (d, c, tt, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) <<  0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >>  4);

  c = c & 0x0fffffff;

  #ifdef _unroll
  #pragma unroll
  #endif
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

    u32 s = BOX (((c00 >>  0) & 0xff), 0, s_skb)
           | BOX (((c06 >>  0) & 0xff)
                 |((c07 >>  0) & 0xff), 1, s_skb)
           | BOX (((c13 >>  0) & 0xff)
                 |((c06 >>  8) & 0xff), 2, s_skb)
           | BOX (((c20 >>  0) & 0xff)
                 |((c13 >>  8) & 0xff)
                 |((c06 >> 16) & 0xff), 3, s_skb);

    const u32 d00 = (d >>  0) & 0x00003c3f;
    const u32 d07 = (d >>  7) & 0x00003f03;
    const u32 d21 = (d >> 21) & 0x0000000f;
    const u32 d22 = (d >> 22) & 0x00000030;

    u32 t = BOX (((d00 >>  0) & 0xff), 4, s_skb)
           | BOX (((d07 >>  0) & 0xff)
                 |((d00 >>  8) & 0xff), 5, s_skb)
           | BOX (((d07 >>  8) & 0xff), 6, s_skb)
           | BOX (((d21 >>  0) & 0xff)
                 |((d22 >>  0) & 0xff), 7, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = rotl32_S (Kc[i], 2u);
    Kd[i] = rotl32_S (Kd[i], 2u);
  }
}

void AES256_ExpandKey (u32 *userkey, u32 *rek, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  rek[0] = userkey[0];
  rek[1] = userkey[1];
  rek[2] = userkey[2];
  rek[3] = userkey[3];
  rek[4] = userkey[4];
  rek[5] = userkey[5];
  rek[6] = userkey[6];
  rek[7] = userkey[7];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0, j = 0; i < 7; i += 1, j += 8)
  {
    const u32 temp1 = rek[j + 7];

    rek[j +  8] = rek[j + 0]
                ^ (s_te2[(temp1 >> 16) & 0xff] & 0xff000000)
                ^ (s_te3[(temp1 >>  8) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp1 >>  0) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp1 >> 24) & 0xff] & 0x000000ff)
                ^ rcon[i];
    rek[j +  9] = rek[j + 1] ^ rek[j +  8];
    rek[j + 10] = rek[j + 2] ^ rek[j +  9];
    rek[j + 11] = rek[j + 3] ^ rek[j + 10];

    if (i == 6) continue;

    const u32 temp2 = rek[j + 11];

    rek[j + 12] = rek[j + 4]
                ^ (s_te2[(temp2 >> 24) & 0xff] & 0xff000000)
                ^ (s_te3[(temp2 >> 16) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp2 >>  8) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp2 >>  0) & 0xff] & 0x000000ff);
    rek[j + 13] = rek[j + 5] ^ rek[j + 12];
    rek[j + 14] = rek[j + 6] ^ rek[j + 13];
    rek[j + 15] = rek[j + 7] ^ rek[j + 14];
  }
}

void AES256_InvertKey (u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0, j = 56; i < 28; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 1, j = 4; i < 14; i += 1, j += 4)
  {
    rdk[j + 0] =
      s_td0[s_te1[(rdk[j + 0] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 0] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 0] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 0] >>  0) & 0xff] & 0xff];

    rdk[j + 1] =
      s_td0[s_te1[(rdk[j + 1] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 1] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 1] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 1] >>  0) & 0xff] & 0xff];

    rdk[j + 2] =
      s_td0[s_te1[(rdk[j + 2] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 2] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 2] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 2] >>  0) & 0xff] & 0xff];

    rdk[j + 3] =
      s_td0[s_te1[(rdk[j + 3] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 3] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 3] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 3] >>  0) & 0xff] & 0xff];
  }
}

void AES256_decrypt (const u32 *in, u32 *out, const u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 t0 = in[0] ^ rdk[0];
  u32 t1 = in[1] ^ rdk[1];
  u32 t2 = in[2] ^ rdk[2];
  u32 t3 = in[3] ^ rdk[3];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 4; i < 56; i += 4)
  {
    const uchar4 x0 = as_uchar4 (t0);
    const uchar4 x1 = as_uchar4 (t1);
    const uchar4 x2 = as_uchar4 (t2);
    const uchar4 x3 = as_uchar4 (t3);

    t0 = s_td0[x0.s3] ^ s_td1[x3.s2] ^ s_td2[x2.s1] ^ s_td3[x1.s0] ^ rdk[i + 0];
    t1 = s_td0[x1.s3] ^ s_td1[x0.s2] ^ s_td2[x3.s1] ^ s_td3[x2.s0] ^ rdk[i + 1];
    t2 = s_td0[x2.s3] ^ s_td1[x1.s2] ^ s_td2[x0.s1] ^ s_td3[x3.s0] ^ rdk[i + 2];
    t3 = s_td0[x3.s3] ^ s_td1[x2.s2] ^ s_td2[x1.s1] ^ s_td3[x0.s0] ^ rdk[i + 3];
  }

  out[0] = (s_td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[56];

  out[1] = (s_td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[57];

  out[2] = (s_td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[58];

  out[3] = (s_td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[59];
}

void md4_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[4])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  MD4_STEP_S (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

  MD4_STEP_S (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

  MD4_STEP_S (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

void sha1_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5])
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

void hmac_sha1_pad_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform_S (w0, w1, w2, w3, opad);
}

void hmac_sha1_run_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5], u32 digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_S (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_S (w0, w1, w2, w3, digest);
}

void sha1_transform_V (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[5])
{
  u32x A = digest[0];
  u32x B = digest[1];
  u32x C = digest[2];
  u32x D = digest[3];
  u32x E = digest[4];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

void hmac_sha1_pad_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[5], u32x opad[5])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform_V (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform_V (w0, w1, w2, w3, opad);
}

void hmac_sha1_run_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[5], u32x opad[5], u32x digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_V (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_V (w0, w1, w2, w3, digest);
}

__constant u64a k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

void sha512_transform_S (const u64 w0[4], const u64 w1[4], const u64 w2[4], const u64 w3[4], u64 digest[8])
{
  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  u64 w0_t = w0[0];
  u64 w1_t = w0[1];
  u64 w2_t = w0[2];
  u64 w3_t = w0[3];
  u64 w4_t = w1[0];
  u64 w5_t = w1[1];
  u64 w6_t = w1[2];
  u64 w7_t = w1[3];
  u64 w8_t = w2[0];
  u64 w9_t = w2[1];
  u64 wa_t = w2[2];
  u64 wb_t = w2[3];
  u64 wc_t = w3[0];
  u64 wd_t = w3[1];
  u64 we_t = w3[2];
  u64 wf_t = w3[3];

  #define ROUND_EXPAND_S()                            \
  {                                                   \
    w0_t = SHA512_EXPAND_S (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND_S (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND_S (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND_S (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND_S (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND_S (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND_S (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND_S (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND_S (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND_S (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND_S (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND_S (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND_S (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND_S (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND_S (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND_S (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP_S(i)                                                                   \
  {                                                                                         \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND_S (); ROUND_STEP_S (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

void hmac_sha512_pad_S (u64 w0[4], u64 w1[4], u64 w2[4], u64 w3[4], u64 ipad[8], u64 opad[8])
{
  w0[0] = w0[0] ^ 0x3636363636363636;
  w0[1] = w0[1] ^ 0x3636363636363636;
  w0[2] = w0[2] ^ 0x3636363636363636;
  w0[3] = w0[3] ^ 0x3636363636363636;
  w1[0] = w1[0] ^ 0x3636363636363636;
  w1[1] = w1[1] ^ 0x3636363636363636;
  w1[2] = w1[2] ^ 0x3636363636363636;
  w1[3] = w1[3] ^ 0x3636363636363636;
  w2[0] = w2[0] ^ 0x3636363636363636;
  w2[1] = w2[1] ^ 0x3636363636363636;
  w2[2] = w2[2] ^ 0x3636363636363636;
  w2[3] = w2[3] ^ 0x3636363636363636;
  w3[0] = w3[0] ^ 0x3636363636363636;
  w3[1] = w3[1] ^ 0x3636363636363636;
  w3[2] = w3[2] ^ 0x3636363636363636;
  w3[3] = w3[3] ^ 0x3636363636363636;

  ipad[0] = SHA512M_A;
  ipad[1] = SHA512M_B;
  ipad[2] = SHA512M_C;
  ipad[3] = SHA512M_D;
  ipad[4] = SHA512M_E;
  ipad[5] = SHA512M_F;
  ipad[6] = SHA512M_G;
  ipad[7] = SHA512M_H;

  sha512_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a6a6a6a6a;

  opad[0] = SHA512M_A;
  opad[1] = SHA512M_B;
  opad[2] = SHA512M_C;
  opad[3] = SHA512M_D;
  opad[4] = SHA512M_E;
  opad[5] = SHA512M_F;
  opad[6] = SHA512M_G;
  opad[7] = SHA512M_H;

  sha512_transform_S (w0, w1, w2, w3, opad);
}

void hmac_sha512_run_S (u64 w0[4], u64 w1[4], u64 w2[4], u64 w3[4], u64 ipad[8], u64 opad[8], u64 digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_S (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x8000000000000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_S (w0, w1, w2, w3, digest);
}

void sha512_transform_V (const u64x w0[4], const u64x w1[4], const u64x w2[4], const u64x w3[4], u64x digest[8])
{
  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

  u64x w0_t = w0[0];
  u64x w1_t = w0[1];
  u64x w2_t = w0[2];
  u64x w3_t = w0[3];
  u64x w4_t = w1[0];
  u64x w5_t = w1[1];
  u64x w6_t = w1[2];
  u64x w7_t = w1[3];
  u64x w8_t = w2[0];
  u64x w9_t = w2[1];
  u64x wa_t = w2[2];
  u64x wb_t = w2[3];
  u64x wc_t = w3[0];
  u64x wd_t = w3[1];
  u64x we_t = w3[2];
  u64x wf_t = w3[3];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

void hmac_sha512_run_V (u64x w0[4], u64x w1[4], u64x w2[4], u64x w3[4], u64x ipad[8], u64x opad[8], u64x digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_V (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x8000000000000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_V (w0, w1, w2, w3, digest);
}

__kernel void m15300_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  u32 w1[4];

  w1[0] = pws[gid].i[4];
  w1[1] = pws[gid].i[5];
  w1[2] = pws[gid].i[6];
  w1[3] = pws[gid].i[7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len;

  append_0x80_2x4_S (w0, w1, pw_len);

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  /**
   * main
   */

  /**
   * salt == SID
   */

  const u32 salt_len = esalt_bufs[digests_offset].SID_len;

  u32 digest_context[5];

  /* local credentials */
  if (esalt_bufs[digests_offset].context == 1)
  {
    digest_context[0] = SHA1M_A;
    digest_context[1] = SHA1M_B;
    digest_context[2] = SHA1M_C;
    digest_context[3] = SHA1M_D;
    digest_context[4] = SHA1M_E;

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);

    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);

    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);

    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = 0;
    w3[3] = pw_len * 2 * 8;

    sha1_transform_S (w0, w1, w2, w3, digest_context);
  }
  /* domain credentials */
  else if (esalt_bufs[digests_offset].context == 2)
  {
    digest_context[0] = MD4M_A;
    digest_context[1] = MD4M_B;
    digest_context[2] = MD4M_C;
    digest_context[3] = MD4M_D;

    w3[2] = pw_len * 2 * 8;

    md4_transform_S (w0, w1, w2, w3, digest_context);

    digest_context[0] = swap32_S (digest_context[0]);
    digest_context[1] = swap32_S (digest_context[1]);
    digest_context[2] = swap32_S (digest_context[2]);
    digest_context[3] = swap32_S (digest_context[3]);
    digest_context[4] = 0;
  }
  /* initialize hmac-sha1 */

   /**
   * pads
   */

  w0[0] = digest_context[0];
  w0[1] = digest_context[1];
  w0[2] = digest_context[2];
  w0[3] = digest_context[3];
  w1[0] = digest_context[4];
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  u32 ipad[5];
  u32 opad[5];

  hmac_sha1_pad_S (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad[0] = ipad[0];
  tmps[gid].ipad[1] = ipad[1];
  tmps[gid].ipad[2] = ipad[2];
  tmps[gid].ipad[3] = ipad[3];
  tmps[gid].ipad[4] = ipad[4];

  tmps[gid].opad[0] = opad[0];
  tmps[gid].opad[1] = opad[1];
  tmps[gid].opad[2] = opad[2];
  tmps[gid].opad[3] = opad[3];
  tmps[gid].opad[4] = opad[4];

  /**
   * hmac1
   */

  w0[0] = esalt_bufs[digests_offset].SID[ 0];
  w0[1] = esalt_bufs[digests_offset].SID[ 1];
  w0[2] = esalt_bufs[digests_offset].SID[ 2];
  w0[3] = esalt_bufs[digests_offset].SID[ 3];
  w1[0] = esalt_bufs[digests_offset].SID[ 4];
  w1[1] = esalt_bufs[digests_offset].SID[ 5];
  w1[2] = esalt_bufs[digests_offset].SID[ 6];
  w1[3] = esalt_bufs[digests_offset].SID[ 7];
  w2[0] = esalt_bufs[digests_offset].SID[ 8];
  w2[1] = esalt_bufs[digests_offset].SID[ 9];
  w2[2] = esalt_bufs[digests_offset].SID[10];
  w2[3] = esalt_bufs[digests_offset].SID[11];
  w3[0] = esalt_bufs[digests_offset].SID[12];
  w3[1] = esalt_bufs[digests_offset].SID[13];
  w3[2] = esalt_bufs[digests_offset].SID[14];
  w3[3] = esalt_bufs[digests_offset].SID[15];

  sha1_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = esalt_bufs[digests_offset].SID[16 +  0];
  w0[1] = esalt_bufs[digests_offset].SID[16 +  1];
  w0[2] = esalt_bufs[digests_offset].SID[16 +  2];
  w0[3] = esalt_bufs[digests_offset].SID[16 +  3];
  w1[0] = esalt_bufs[digests_offset].SID[16 +  4];
  w1[1] = esalt_bufs[digests_offset].SID[16 +  5];
  w1[2] = esalt_bufs[digests_offset].SID[16 +  6];
  w1[3] = esalt_bufs[digests_offset].SID[16 +  7];
  w2[0] = esalt_bufs[digests_offset].SID[16 +  8];
  w2[1] = esalt_bufs[digests_offset].SID[16 +  9];
  w2[2] = esalt_bufs[digests_offset].SID[16 + 10];
  w2[3] = esalt_bufs[digests_offset].SID[16 + 11];
  w3[0] = esalt_bufs[digests_offset].SID[16 + 12];
  w3[1] = esalt_bufs[digests_offset].SID[16 + 13];
  w3[2] = 0;
  w3[3] = (64 + salt_len) * 8;

  u32 key[5];

  hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, key);
  /* this key is used as password for pbkdf2-hmac-* */

  tmps[gid].userKey[0] = key[0];
  tmps[gid].userKey[1] = key[1];
  tmps[gid].userKey[2] = key[2];
  tmps[gid].userKey[3] = key[3];
  tmps[gid].userKey[4] = key[4];

  /* if DPAPImk version 1, pbkdf-hmac-sha1 is used */
  if (esalt_bufs[digests_offset].version == 1)
  {
    /**
     * pads
     */

    w0[0] = key[0];
    w0[1] = key[1];
    w0[2] = key[2];
    w0[3] = key[3];
    w1[0] = key[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha1_pad_S (w0, w1, w2, w3, ipad, opad);

    tmps[gid].ipad[0] = ipad[0];
    tmps[gid].ipad[1] = ipad[1];
    tmps[gid].ipad[2] = ipad[2];
    tmps[gid].ipad[3] = ipad[3];
    tmps[gid].ipad[4] = ipad[4];

    tmps[gid].opad[0] = opad[0];
    tmps[gid].opad[1] = opad[1];
    tmps[gid].opad[2] = opad[2];
    tmps[gid].opad[3] = opad[3];
    tmps[gid].opad[4] = opad[4];

    /**
     * hmac1
     */

    w0[0] = esalt_bufs[digests_offset].iv[0];
    w0[1] = esalt_bufs[digests_offset].iv[1];
    w0[2] = esalt_bufs[digests_offset].iv[2];
    w0[3] = esalt_bufs[digests_offset].iv[3];
    w1[0] = 1;
    w1[1] = 0x80000000;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 16 + 4) * 8;

    u32 digest[5];

    hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, digest);

    tmps[gid].dgst[0] = digest[0];
    tmps[gid].dgst[1] = digest[1];
    tmps[gid].dgst[2] = digest[2];
    tmps[gid].dgst[3] = digest[3];
    tmps[gid].dgst[4] = digest[4];

    tmps[gid].out[0]  = digest[0];
    tmps[gid].out[1]  = digest[1];
    tmps[gid].out[2]  = digest[2];
    tmps[gid].out[3]  = digest[3];
    tmps[gid].out[4]  = digest[4];

    /* We need bigger output! */
    w0[0] = esalt_bufs[digests_offset].iv[0];
    w0[1] = esalt_bufs[digests_offset].iv[1];
    w0[2] = esalt_bufs[digests_offset].iv[2];
    w0[3] = esalt_bufs[digests_offset].iv[3];
    w1[0] = 2;
    w1[1] = 0x80000000;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 16 + 4) * 8;

    hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, digest);

    tmps[gid].dgst[5] = digest[0];
    tmps[gid].dgst[6] = digest[1];
    tmps[gid].dgst[7] = digest[2];
    tmps[gid].dgst[8] = digest[3];
    tmps[gid].dgst[9] = digest[4];

    tmps[gid].out[5]  = digest[0];
    tmps[gid].out[6]  = digest[1];
    tmps[gid].out[7]  = digest[2];
    tmps[gid].out[8]  = digest[3];
    tmps[gid].out[9]  = digest[4];
  }
  /* if DPAPImk version 2, pbkdf-hmac-sha512 is used*/
  else if (esalt_bufs[digests_offset].version == 2)
  {
    u64 w0_x64[4];
    u64 w1_x64[4];
    u64 w2_x64[4];
    u64 w3_x64[4];

    w0_x64[0] = hl32_to_64_S (key[0], key[1]);
    w0_x64[1] = hl32_to_64_S (key[2], key[3]);
    w0_x64[2] = hl32_to_64_S (key[4], 0);
    w0_x64[3] = 0;
    w1_x64[0] = 0;
    w1_x64[1] = 0;
    w1_x64[2] = 0;
    w1_x64[3] = 0;
    w2_x64[0] = 0;
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = 0;

    u64 ipad64[8];
    u64 opad64[8];

    hmac_sha512_pad_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64);

    tmps[gid].ipad64[0] = ipad64[0];
    tmps[gid].ipad64[1] = ipad64[1];
    tmps[gid].ipad64[2] = ipad64[2];
    tmps[gid].ipad64[3] = ipad64[3];
    tmps[gid].ipad64[4] = ipad64[4];
    tmps[gid].ipad64[5] = ipad64[5];
    tmps[gid].ipad64[6] = ipad64[6];
    tmps[gid].ipad64[7] = ipad64[7];

    tmps[gid].opad64[0] = opad64[0];
    tmps[gid].opad64[1] = opad64[1];
    tmps[gid].opad64[2] = opad64[2];
    tmps[gid].opad64[3] = opad64[3];
    tmps[gid].opad64[4] = opad64[4];
    tmps[gid].opad64[5] = opad64[5];
    tmps[gid].opad64[6] = opad64[6];
    tmps[gid].opad64[7] = opad64[7];

    w0_x64[0] = hl32_to_64_S (esalt_bufs[digests_offset].iv[0], esalt_bufs[digests_offset].iv[1]);
    w0_x64[1] = hl32_to_64_S (esalt_bufs[digests_offset].iv[2], esalt_bufs[digests_offset].iv[3]);
    w0_x64[2] = hl32_to_64_S (1, 0x80000000);
    w0_x64[3] = 0;
    w1_x64[0] = 0;
    w1_x64[1] = 0;
    w1_x64[2] = 0;
    w1_x64[3] = 0;
    w2_x64[0] = 0;
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = (128 + 16 + 4) * 8;

    u64 dgst64[8];

    hmac_sha512_run_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64, dgst64);

    tmps[gid].dgst64[0] = dgst64[0];
    tmps[gid].dgst64[1] = dgst64[1];
    tmps[gid].dgst64[2] = dgst64[2];
    tmps[gid].dgst64[3] = dgst64[3];
    tmps[gid].dgst64[4] = dgst64[4];
    tmps[gid].dgst64[5] = dgst64[5];
    tmps[gid].dgst64[6] = dgst64[6];
    tmps[gid].dgst64[7] = dgst64[7];

    tmps[gid].out64[0]  = dgst64[0];
    tmps[gid].out64[1]  = dgst64[1];
    tmps[gid].out64[2]  = dgst64[2];
    tmps[gid].out64[3]  = dgst64[3];
    tmps[gid].out64[4]  = dgst64[4];
    tmps[gid].out64[5]  = dgst64[5];
    tmps[gid].out64[6]  = dgst64[6];
    tmps[gid].out64[7]  = dgst64[7];
  }
}

__kernel void m15300_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  if (esalt_bufs[digests_offset].version == 1)
  {
    u32x ipad[5];
    u32x opad[5];

    ipad[0] = packv (tmps, ipad, gid, 0);
    ipad[1] = packv (tmps, ipad, gid, 1);
    ipad[2] = packv (tmps, ipad, gid, 2);
    ipad[3] = packv (tmps, ipad, gid, 3);
    ipad[4] = packv (tmps, ipad, gid, 4);

    opad[0] = packv (tmps, opad, gid, 0);
    opad[1] = packv (tmps, opad, gid, 1);
    opad[2] = packv (tmps, opad, gid, 2);
    opad[3] = packv (tmps, opad, gid, 3);
    opad[4] = packv (tmps, opad, gid, 4);

    /**
     * iter1
     */

    for (u32 i = 0; i < 8; i += 5)
    {
      u32x dgst[5];
      u32x out[5];

      dgst[0] = packv (tmps, dgst, gid, i + 0);
      dgst[1] = packv (tmps, dgst, gid, i + 1);
      dgst[2] = packv (tmps, dgst, gid, i + 2);
      dgst[3] = packv (tmps, dgst, gid, i + 3);
      dgst[4] = packv (tmps, dgst, gid, i + 4);

      out[0]  = packv (tmps, out, gid, i + 0);
      out[1]  = packv (tmps, out, gid, i + 1);
      out[2]  = packv (tmps, out, gid, i + 2);
      out[3]  = packv (tmps, out, gid, i + 3);
      out[4]  = packv (tmps, out, gid, i + 4);

      for (u32 j = 0; j < loop_cnt; j++)
      {
        u32x w0[4];
        u32x w1[4];
        u32x w2[4];
        u32x w3[4];

        /* Microsoft PBKDF2 implementation. On purpose?
           Misunderstanding of them? Dunno...
        */
        w0[0] = out[0];
        w0[1] = out[1];
        w0[2] = out[2];
        w0[3] = out[3];
        w1[0] = out[4];
        w1[1] = 0x80000000;
        w1[2] = 0;
        w1[3] = 0;
        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;
        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = (64 + 20) * 8;

        hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

        out[0] ^= dgst[0];
        out[1] ^= dgst[1];
        out[2] ^= dgst[2];
        out[3] ^= dgst[3];
        out[4] ^= dgst[4];
      }

      unpackv (tmps, dgst, gid, i + 0, dgst[0]);
      unpackv (tmps, dgst, gid, i + 1, dgst[1]);
      unpackv (tmps, dgst, gid, i + 2, dgst[2]);
      unpackv (tmps, dgst, gid, i + 3, dgst[3]);
      unpackv (tmps, dgst, gid, i + 4, dgst[4]);

      unpackv (tmps, out, gid, i + 0, out[0]);
      unpackv (tmps, out, gid, i + 1, out[1]);
      unpackv (tmps, out, gid, i + 2, out[2]);
      unpackv (tmps, out, gid, i + 3, out[3]);
      unpackv (tmps, out, gid, i + 4, out[4]);
    }
  }
  else if (esalt_bufs[digests_offset].version == 2)
  {
    u64x ipad[8];
    u64x opad[8];

    ipad[0] = pack64v (tmps, ipad64, gid, 0);
    ipad[1] = pack64v (tmps, ipad64, gid, 1);
    ipad[2] = pack64v (tmps, ipad64, gid, 2);
    ipad[3] = pack64v (tmps, ipad64, gid, 3);
    ipad[4] = pack64v (tmps, ipad64, gid, 4);
    ipad[5] = pack64v (tmps, ipad64, gid, 5);
    ipad[6] = pack64v (tmps, ipad64, gid, 6);
    ipad[7] = pack64v (tmps, ipad64, gid, 7);

    opad[0] = pack64v (tmps, opad64, gid, 0);
    opad[1] = pack64v (tmps, opad64, gid, 1);
    opad[2] = pack64v (tmps, opad64, gid, 2);
    opad[3] = pack64v (tmps, opad64, gid, 3);
    opad[4] = pack64v (tmps, opad64, gid, 4);
    opad[5] = pack64v (tmps, opad64, gid, 5);
    opad[6] = pack64v (tmps, opad64, gid, 6);
    opad[7] = pack64v (tmps, opad64, gid, 7);

    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst64, gid, 0);
    dgst[1] = pack64v (tmps, dgst64, gid, 1);
    dgst[2] = pack64v (tmps, dgst64, gid, 2);
    dgst[3] = pack64v (tmps, dgst64, gid, 3);
    dgst[4] = pack64v (tmps, dgst64, gid, 4);
    dgst[5] = pack64v (tmps, dgst64, gid, 5);
    dgst[6] = pack64v (tmps, dgst64, gid, 6);
    dgst[7] = pack64v (tmps, dgst64, gid, 7);

    out[0]  = pack64v (tmps, out64, gid, 0);
    out[1]  = pack64v (tmps, out64, gid, 1);
    out[2]  = pack64v (tmps, out64, gid, 2);
    out[3]  = pack64v (tmps, out64, gid, 3);
    out[4]  = pack64v (tmps, out64, gid, 4);
    out[5]  = pack64v (tmps, out64, gid, 5);
    out[6]  = pack64v (tmps, out64, gid, 6);
    out[7]  = pack64v (tmps, out64, gid, 7);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u64x w0[4];
      u64x w1[4];
      u64x w2[4];
      u64x w3[4];

      /* Microsoft PBKDF2 implementation. On purpose?
         Misunderstanding of them? Dunno...
      */
      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0x8000000000000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (128 + 64) * 8;

      hmac_sha512_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst64, gid, 0, dgst[0]);
    unpackv (tmps, dgst64, gid, 1, dgst[1]);
    unpackv (tmps, dgst64, gid, 2, dgst[2]);
    unpackv (tmps, dgst64, gid, 3, dgst[3]);
    unpackv (tmps, dgst64, gid, 4, dgst[4]);
    unpackv (tmps, dgst64, gid, 5, dgst[5]);
    unpackv (tmps, dgst64, gid, 6, dgst[6]);
    unpackv (tmps, dgst64, gid, 7, dgst[7]);

    unpackv (tmps, out64, gid, 0, out[0]);
    unpackv (tmps, out64, gid, 1, out[1]);
    unpackv (tmps, out64, gid, 2, out[2]);
    unpackv (tmps, out64, gid, 3, out[3]);
    unpackv (tmps, out64, gid, 4, out[4]);
    unpackv (tmps, out64, gid, 5, out[5]);
    unpackv (tmps, out64, gid, 6, out[6]);
    unpackv (tmps, out64, gid, 7, out[7]);
  }
}

__kernel void m15300_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  if (esalt_bufs[digests_offset].version == 1)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    u32 ipad[5];
    u32 opad[5];

  /**
   * shared
   */

    __local u32 s_SPtrans[8][64];
    __local u32 s_skb[8][64];

    for (u32 i = lid; i < 64; i += lsz)
    {
      s_SPtrans[0][i] = c_SPtrans[0][i];
      s_SPtrans[1][i] = c_SPtrans[1][i];
      s_SPtrans[2][i] = c_SPtrans[2][i];
      s_SPtrans[3][i] = c_SPtrans[3][i];
      s_SPtrans[4][i] = c_SPtrans[4][i];
      s_SPtrans[5][i] = c_SPtrans[5][i];
      s_SPtrans[6][i] = c_SPtrans[6][i];
      s_SPtrans[7][i] = c_SPtrans[7][i];

      s_skb[0][i] = c_skb[0][i];
      s_skb[1][i] = c_skb[1][i];
      s_skb[2][i] = c_skb[2][i];
      s_skb[3][i] = c_skb[3][i];
      s_skb[4][i] = c_skb[4][i];
      s_skb[5][i] = c_skb[5][i];
      s_skb[6][i] = c_skb[6][i];
      s_skb[7][i] = c_skb[7][i];
    }

    barrier (CLK_LOCAL_MEM_FENCE);

    if (gid >= gid_max) return;

    u32 key[6];

    key[0] = swap32_S (tmps[gid].out[0]);
    key[1] = swap32_S (tmps[gid].out[1]);
    key[2] = swap32_S (tmps[gid].out[2]);
    key[3] = swap32_S (tmps[gid].out[3]);
    key[4] = swap32_S (tmps[gid].out[4]);
    key[5] = swap32_S (tmps[gid].out[5]);

    u32 iv[2];

    iv[0]  = swap32_S (tmps[gid].out[6]);
    iv[1]  = swap32_S (tmps[gid].out[7]);

    u32 decrypted[26];

    /* Construct 3DES keys */

    const u32 a = (key[0]);
    const u32 b = (key[1]);

    u32 Ka[16];
    u32 Kb[16];

    _des_crypt_keysetup (a, b, Ka, Kb, s_skb);

    const u32 c = (key[2]);
    const u32 d = (key[3]);

    u32 Kc[16];
    u32 Kd[16];

    _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

    const u32 e = (key[4]);
    const u32 f = (key[5]);

    u32 Ke[16];
    u32 Kf[16];

    _des_crypt_keysetup (e, f, Ke, Kf, s_skb);

    u32 contents_pos;
    u32 contents_off;
    u32 wx_off;

    for (wx_off = 0, contents_pos = 0, contents_off = 0; contents_pos < esalt_bufs[digests_offset].contents_len; wx_off += 2, contents_pos += 8, contents_off += 2)
    {
      /* First Pass */

      u32 data[2];

      data[0] = swap32_S (esalt_bufs[digests_offset].contents[contents_off + 0]);
      data[1] = swap32_S (esalt_bufs[digests_offset].contents[contents_off + 1]);

      u32 p1[2];

      _des_crypt_decrypt (p1, data, Ke, Kf, s_SPtrans);

      /* Second Pass */

      u32 p2[2];

      _des_crypt_encrypt (p2, p1, Kc, Kd, s_SPtrans);

      /* Third Pass */

      u32 out[2];

      _des_crypt_decrypt (out, p2, Ka, Kb, s_SPtrans);

      out[0] ^= iv[0];
      out[1] ^= iv[1];

      decrypted[wx_off + 0] = out[0];
      decrypted[wx_off + 1] = out[1];

      iv[0] = data[0];
      iv[1] = data[1];
    }

    u32 hmacSalt[4];
    u32 expectedHmac[5];
    u32 lastKey[16];

    hmacSalt[0]     = swap32_S (decrypted[0]);
    hmacSalt[1]     = swap32_S (decrypted[1]);
    hmacSalt[2]     = swap32_S (decrypted[2]);
    hmacSalt[3]     = swap32_S (decrypted[3]);

    expectedHmac[0] = swap32_S (decrypted[4 + 0]);
    expectedHmac[1] = swap32_S (decrypted[4 + 1]);
    expectedHmac[2] = swap32_S (decrypted[4 + 2]);
    expectedHmac[3] = swap32_S (decrypted[4 + 3]);
    expectedHmac[4] = swap32_S (decrypted[4 + 4]);

    for(int i = 0; i < 16; i++)
    {
      lastKey[i] = decrypted[i + 26 - 16];
    }

    w0[0] = tmps[gid].userKey[0];
    w0[1] = tmps[gid].userKey[1];
    w0[2] = tmps[gid].userKey[2];
    w0[3] = tmps[gid].userKey[3];
    w1[0] = tmps[gid].userKey[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha1_pad_S (w0, w1, w2, w3, ipad, opad);

    /**
     * hmac1
     */

    w0[0] = hmacSalt[0];
    w0[1] = hmacSalt[1];
    w0[2] = hmacSalt[2];
    w0[3] = hmacSalt[3];
    w1[0] = 0x80000000;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 16) * 8;

    u32 digest[5];

    hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha1_pad_S (w0, w1, w2, w3, ipad, opad);

    /**
     * hmac1
     */

    w0[0] = swap32_S (lastKey[ 0]);
    w0[1] = swap32_S (lastKey[ 1]);
    w0[2] = swap32_S (lastKey[ 2]);
    w0[3] = swap32_S (lastKey[ 3]);
    w1[0] = swap32_S (lastKey[ 4]);
    w1[1] = swap32_S (lastKey[ 5]);
    w1[2] = swap32_S (lastKey[ 6]);
    w1[3] = swap32_S (lastKey[ 7]);
    w2[0] = swap32_S (lastKey[ 8]);
    w2[1] = swap32_S (lastKey[ 9]);
    w2[2] = swap32_S (lastKey[10]);
    w2[3] = swap32_S (lastKey[11]);
    w3[0] = swap32_S (lastKey[12]);
    w3[1] = swap32_S (lastKey[13]);
    w3[2] = swap32_S (lastKey[14]);
    w3[3] = swap32_S (lastKey[15]);

    sha1_transform_S (w0, w1, w2, w3, ipad);

    w0[0] = 0x80000000;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 16 * 4) * 8;

    hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, digest);

    #define il_pos 0

    if (  expectedHmac[0] == digest[0]
      &&  expectedHmac[1] == digest[1]
      &&  expectedHmac[2] == digest[2]
      &&  expectedHmac[3] == digest[3]
      &&  expectedHmac[4] == digest[4])
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
    }
  }
  else if (esalt_bufs[digests_offset].version == 2)
  {
    /**
     * aes shared
     */

    #ifdef REAL_SHM

    __local u32 s_td0[256];
    __local u32 s_td1[256];
    __local u32 s_td2[256];
    __local u32 s_td3[256];
    __local u32 s_td4[256];

    __local u32 s_te0[256];
    __local u32 s_te1[256];
    __local u32 s_te2[256];
    __local u32 s_te3[256];
    __local u32 s_te4[256];

    for (u32 i = lid; i < 256; i += lsz)
    {
      s_td0[i] = td0[i];
      s_td1[i] = td1[i];
      s_td2[i] = td2[i];
      s_td3[i] = td3[i];
      s_td4[i] = td4[i];

      s_te0[i] = te0[i];
      s_te1[i] = te1[i];
      s_te2[i] = te2[i];
      s_te3[i] = te3[i];
      s_te4[i] = te4[i];
    }

    barrier (CLK_LOCAL_MEM_FENCE);

    #else

    __constant u32a *s_td0 = td0;
    __constant u32a *s_td1 = td1;
    __constant u32a *s_td2 = td2;
    __constant u32a *s_td3 = td3;
    __constant u32a *s_td4 = td4;

    __constant u32a *s_te0 = te0;
    __constant u32a *s_te1 = te1;
    __constant u32a *s_te2 = te2;
    __constant u32a *s_te3 = te3;
    __constant u32a *s_te4 = te4;

    #endif

    if (gid >= gid_max) return;

    /* Construct AES key */

    u32 key[8];

    key[0] = h32_from_64_S (tmps[gid].out64[0]);
    key[1] = l32_from_64_S (tmps[gid].out64[0]);
    key[2] = h32_from_64_S (tmps[gid].out64[1]);
    key[3] = l32_from_64_S (tmps[gid].out64[1]);
    key[4] = h32_from_64_S (tmps[gid].out64[2]);
    key[5] = l32_from_64_S (tmps[gid].out64[2]);
    key[6] = h32_from_64_S (tmps[gid].out64[3]);
    key[7] = l32_from_64_S (tmps[gid].out64[3]);

    u32 iv[4];

    iv[0]  = h32_from_64_S (tmps[gid].out64[4]);
    iv[1]  = l32_from_64_S (tmps[gid].out64[4]);
    iv[2]  = h32_from_64_S (tmps[gid].out64[5]);
    iv[3]  = l32_from_64_S (tmps[gid].out64[5]);

    #define KEYLEN 60

    u32 rek[KEYLEN];

    AES256_ExpandKey (key, rek, s_te0, s_te1, s_te2, s_te3, s_te4);

    u32 rdk[KEYLEN];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (u32 i = 0; i < KEYLEN; i++) rdk[i] = rek[i];

    AES256_InvertKey (rdk, s_td0, s_td1, s_td2, s_td3, s_td4, s_te0, s_te1, s_te2, s_te3, s_te4);

    /* 144 bytes */
    u32 decrypted[36] = { 0 };

    u32 contents_pos;
    u32 contents_off;
    u32 wx_off;

    for (wx_off = 0, contents_pos = 0, contents_off = 0; contents_pos < esalt_bufs[digests_offset].contents_len; wx_off += 4, contents_pos += 16, contents_off += 4)
    {
      u32 data[4];

      data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
      data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
      data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
      data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

      u32 out[4];

      AES256_decrypt (data, out, rdk, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      decrypted[wx_off + 0] = out[0];
      decrypted[wx_off + 1] = out[1];
      decrypted[wx_off + 2] = out[2];
      decrypted[wx_off + 3] = out[3];

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }

    u32 hmacSalt[4];
    u32 expectedHmac[16];
    u32 lastKey[16];

    hmacSalt[0] = decrypted[0];
    hmacSalt[1] = decrypted[1];
    hmacSalt[2] = decrypted[2];
    hmacSalt[3] = decrypted[3];

    for(int i = 0; i < 16; i++)
    {
      expectedHmac[i] = decrypted[i + 4];
      lastKey[i]      = decrypted[i + 36 - 16];
    }

    u64 w0_x64[4];
    u64 w1_x64[4];
    u64 w2_x64[4];
    u64 w3_x64[4];

    w0_x64[0] = hl32_to_64_S (tmps[gid].userKey[0], tmps[gid].userKey[1]);
    w0_x64[1] = hl32_to_64_S (tmps[gid].userKey[2], tmps[gid].userKey[3]);
    w0_x64[2] = hl32_to_64_S (tmps[gid].userKey[4], 0);
    w0_x64[3] = 0;
    w1_x64[0] = 0;
    w1_x64[1] = 0;
    w1_x64[2] = 0;
    w1_x64[3] = 0;
    w2_x64[0] = 0;
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = 0;

    u64 ipad64[8];
    u64 opad64[8];

    hmac_sha512_pad_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64);

    w0_x64[0] = hl32_to_64_S (hmacSalt[0], hmacSalt[1]);
    w0_x64[1] = hl32_to_64_S (hmacSalt[2], hmacSalt[3]);
    w0_x64[2] = hl32_to_64_S (0x80000000, 0);
    w0_x64[3] = 0;
    w1_x64[0] = 0;
    w1_x64[1] = 0;
    w1_x64[2] = 0;
    w1_x64[3] = 0;
    w2_x64[0] = 0;
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = (128 + 16) * 8;

    u64 dgst64[8];

    hmac_sha512_run_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64, dgst64);

    u64 encKey[8];

    encKey[0] = dgst64[0];
    encKey[1] = dgst64[1];
    encKey[2] = dgst64[2];
    encKey[3] = dgst64[3];
    encKey[4] = dgst64[4];
    encKey[5] = dgst64[5];
    encKey[6] = dgst64[6];
    encKey[7] = dgst64[7];

    w0_x64[0] = encKey[0];
    w0_x64[1] = encKey[1];
    w0_x64[2] = encKey[2];
    w0_x64[3] = encKey[3];
    w1_x64[0] = encKey[4];
    w1_x64[1] = encKey[5];
    w1_x64[2] = encKey[6];
    w1_x64[3] = encKey[7];
    w2_x64[0] = 0;
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = 0;

    hmac_sha512_pad_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64);

    w0_x64[0] = hl32_to_64_S (lastKey[ 0], lastKey[ 1]);
    w0_x64[1] = hl32_to_64_S (lastKey[ 2], lastKey[ 3]);
    w0_x64[2] = hl32_to_64_S (lastKey[ 4], lastKey[ 5]);
    w0_x64[3] = hl32_to_64_S (lastKey[ 6], lastKey[ 7]);
    w1_x64[0] = hl32_to_64_S (lastKey[ 8], lastKey[ 9]);
    w1_x64[1] = hl32_to_64_S (lastKey[10], lastKey[11]);
    w1_x64[2] = hl32_to_64_S (lastKey[12], lastKey[13]);
    w1_x64[3] = hl32_to_64_S (lastKey[14], lastKey[15]);
    w2_x64[0] = hl32_to_64_S (0x80000000, 0);
    w2_x64[1] = 0;
    w2_x64[2] = 0;
    w2_x64[3] = 0;
    w3_x64[0] = 0;
    w3_x64[1] = 0;
    w3_x64[2] = 0;
    w3_x64[3] = (128 + 16 * 4) * 8;

    hmac_sha512_run_S (w0_x64, w1_x64, w2_x64, w3_x64, ipad64, opad64, dgst64);

    #define il_pos 0

    if (  expectedHmac[ 0] == h32_from_64_S (dgst64[0])
       && expectedHmac[ 1] == l32_from_64_S (dgst64[0])
       && expectedHmac[ 2] == h32_from_64_S (dgst64[1])
       && expectedHmac[ 3] == l32_from_64_S (dgst64[1])
       && expectedHmac[12] == h32_from_64_S (dgst64[6])
       && expectedHmac[13] == l32_from_64_S (dgst64[6])
       && expectedHmac[14] == h32_from_64_S (dgst64[7])
       && expectedHmac[15] == l32_from_64_S (dgst64[7]))
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
    }
  }
}
