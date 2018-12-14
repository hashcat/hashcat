/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

typedef uchar  u8;
typedef ushort u16;
typedef uint   u32;
typedef ulong  u64;

typedef u8  u8a  __attribute__ ((aligned (8)));
typedef u16 u16a __attribute__ ((aligned (8)));
typedef u32 u32a __attribute__ ((aligned (8)));
typedef u64 u64a __attribute__ ((aligned (8)));

#ifndef NEW_SIMD_CODE
#undef  VECT_SIZE
#define VECT_SIZE 1
#endif

#define CONCAT(a, b)       a##b
#define VTYPE(type, width) CONCAT(type, width)

#if VECT_SIZE == 1
typedef uchar   u8x;
typedef ushort  u16x;
typedef uint    u32x;
typedef ulong   u64x;
#else
typedef VTYPE(uchar,  VECT_SIZE)  u8x;
typedef VTYPE(ushort, VECT_SIZE) u16x;
typedef VTYPE(uint,   VECT_SIZE) u32x;
typedef VTYPE(ulong,  VECT_SIZE) u64x;
#endif

DECLSPEC u32 l32_from_64_S (u64 a)
{
  const u32 r = (u32) (a);

  return r;
}

DECLSPEC u32 h32_from_64_S (u64 a)
{
  a >>= 32;

  const u32 r = (u32) (a);

  return r;
}

DECLSPEC u64 hl32_to_64_S (const u32 a, const u32 b)
{
  return as_ulong ((uint2) (b, a));
}

DECLSPEC u32x l32_from_64 (u64x a)
{
  u32x r;

  #if VECT_SIZE == 1
  r    = (u32) a;
  #endif

  #if VECT_SIZE >= 2
  r.s0 = (u32) a.s0;
  r.s1 = (u32) a.s1;
  #endif

  #if VECT_SIZE >= 4
  r.s2 = (u32) a.s2;
  r.s3 = (u32) a.s3;
  #endif

  #if VECT_SIZE >= 8
  r.s4 = (u32) a.s4;
  r.s5 = (u32) a.s5;
  r.s6 = (u32) a.s6;
  r.s7 = (u32) a.s7;
  #endif

  #if VECT_SIZE >= 16
  r.s8 = (u32) a.s8;
  r.s9 = (u32) a.s9;
  r.sa = (u32) a.sa;
  r.sb = (u32) a.sb;
  r.sc = (u32) a.sc;
  r.sd = (u32) a.sd;
  r.se = (u32) a.se;
  r.sf = (u32) a.sf;
  #endif

  return r;
}

DECLSPEC u32x h32_from_64 (u64x a)
{
  a >>= 32;

  u32x r;

  #if VECT_SIZE == 1
  r    = (u32) a;
  #endif

  #if VECT_SIZE >= 2
  r.s0 = (u32) a.s0;
  r.s1 = (u32) a.s1;
  #endif

  #if VECT_SIZE >= 4
  r.s2 = (u32) a.s2;
  r.s3 = (u32) a.s3;
  #endif

  #if VECT_SIZE >= 8
  r.s4 = (u32) a.s4;
  r.s5 = (u32) a.s5;
  r.s6 = (u32) a.s6;
  r.s7 = (u32) a.s7;
  #endif

  #if VECT_SIZE >= 16
  r.s8 = (u32) a.s8;
  r.s9 = (u32) a.s9;
  r.sa = (u32) a.sa;
  r.sb = (u32) a.sb;
  r.sc = (u32) a.sc;
  r.sd = (u32) a.sd;
  r.se = (u32) a.se;
  r.sf = (u32) a.sf;
  #endif

  return r;
}

DECLSPEC u64x hl32_to_64 (const u32x a, const u32x b)
{
  u64x r;

  #if VECT_SIZE == 1
  r    = as_ulong ((uint2) (b,    a));
  #endif

  #if VECT_SIZE >= 2
  r.s0 = as_ulong ((uint2) (b.s0, a.s0));
  r.s1 = as_ulong ((uint2) (b.s1, a.s1));
  #endif

  #if VECT_SIZE >= 4
  r.s2 = as_ulong ((uint2) (b.s2, a.s2));
  r.s3 = as_ulong ((uint2) (b.s3, a.s3));
  #endif

  #if VECT_SIZE >= 8
  r.s4 = as_ulong ((uint2) (b.s4, a.s4));
  r.s5 = as_ulong ((uint2) (b.s5, a.s5));
  r.s6 = as_ulong ((uint2) (b.s6, a.s6));
  r.s7 = as_ulong ((uint2) (b.s7, a.s7));
  #endif

  #if VECT_SIZE >= 16
  r.s8 = as_ulong ((uint2) (b.s8, a.s8));
  r.s9 = as_ulong ((uint2) (b.s9, a.s9));
  r.sa = as_ulong ((uint2) (b.sa, a.sa));
  r.sb = as_ulong ((uint2) (b.sb, a.sb));
  r.sc = as_ulong ((uint2) (b.sc, a.sc));
  r.sd = as_ulong ((uint2) (b.sd, a.sd));
  r.se = as_ulong ((uint2) (b.se, a.se));
  r.sf = as_ulong ((uint2) (b.sf, a.sf));
  #endif

  return r;
}

#ifdef IS_AMD

#if AMD_GCN >= 3
DECLSPEC u32 swap32_S (const u32 v)
{
  u32 r;

  __asm__ ("V_PERM_B32 %0, 0, %1, %2;" : "=v"(r) : "v"(v), "v"(0x00010203));

  return r;
}

DECLSPEC u64 swap64_S (const u64 v)
{
  const u32 v0 = h32_from_64_S (v);
  const u32 v1 = l32_from_64_S (v);

  u32 t0;
  u32 t1;

  __asm__ ("V_PERM_B32 %0, 0, %1, %2;" : "=v"(t0) : "v"(v0), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, 0, %1, %2;" : "=v"(t1) : "v"(v1), "v"(0x00010203));

  const u64 r = hl32_to_64_S (t1, t0);

  return r;
}
#else
DECLSPEC u32 swap32_S (const u32 v)
{
  return as_uint (as_uchar4 (v).s3210);
}

DECLSPEC u64 swap64_S (const u64 v)
{
  return (as_ulong (as_uchar8 (v).s76543210));
}
#endif

DECLSPEC u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64 rotr64_S (const u64 a, const u32 n)
{
  const u32 a0 = h32_from_64_S (a);
  const u32 a1 = l32_from_64_S (a);

  const u32 t0 = (n >= 32) ? amd_bitalign (a0, a1, n - 32) : amd_bitalign (a1, a0, n);
  const u32 t1 = (n >= 32) ? amd_bitalign (a1, a0, n - 32) : amd_bitalign (a0, a1, n);

  const u64 r = hl32_to_64_S (t0, t1);

  return r;
}

DECLSPEC u64 rotl64_S (const u64 a, const u32 n)
{
  return rotr64_S (a, 64 - n);
}

#if AMD_GCN >= 3
DECLSPEC u32x swap32 (const u32x v)
{
  return bitselect (rotate (v, 24u), rotate (v, 8u), 0x00ff00ffu);
}

DECLSPEC u64x swap64 (const u64x v)
{
  const u32x a0 = h32_from_64 (v);
  const u32x a1 = l32_from_64 (v);

  u32x t0;
  u32x t1;

  #if VECT_SIZE == 1
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0) : "v"(0), "v"(a0), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1) : "v"(0), "v"(a1), "v"(0x00010203));
  #endif

  #if VECT_SIZE >= 2
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s0) : "v"(0), "v"(a0.s0), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s0) : "v"(0), "v"(a1.s0), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s1) : "v"(0), "v"(a0.s1), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s1) : "v"(0), "v"(a1.s1), "v"(0x00010203));
  #endif

  #if VECT_SIZE >= 4
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s2) : "v"(0), "v"(a0.s2), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s2) : "v"(0), "v"(a1.s2), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s3) : "v"(0), "v"(a0.s3), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s3) : "v"(0), "v"(a1.s3), "v"(0x00010203));
  #endif

  #if VECT_SIZE >= 8
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s4) : "v"(0), "v"(a0.s4), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s4) : "v"(0), "v"(a1.s4), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s5) : "v"(0), "v"(a0.s5), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s5) : "v"(0), "v"(a1.s5), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s6) : "v"(0), "v"(a0.s6), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s6) : "v"(0), "v"(a1.s6), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s7) : "v"(0), "v"(a0.s7), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s7) : "v"(0), "v"(a1.s7), "v"(0x00010203));
  #endif

  #if VECT_SIZE >= 16
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s8) : "v"(0), "v"(a0.s8), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s8) : "v"(0), "v"(a1.s8), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.s9) : "v"(0), "v"(a0.s9), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.s9) : "v"(0), "v"(a1.s9), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.sa) : "v"(0), "v"(a0.sa), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.sa) : "v"(0), "v"(a1.sa), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.sb) : "v"(0), "v"(a0.sb), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.sb) : "v"(0), "v"(a1.sb), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.sc) : "v"(0), "v"(a0.sc), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.sc) : "v"(0), "v"(a1.sc), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.sd) : "v"(0), "v"(a0.sd), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.sd) : "v"(0), "v"(a1.sd), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.se) : "v"(0), "v"(a0.se), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.se) : "v"(0), "v"(a1.se), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t0.sf) : "v"(0), "v"(a0.sf), "v"(0x00010203));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(t1.sf) : "v"(0), "v"(a1.sf), "v"(0x00010203));
  #endif

  const u64x r = hl32_to_64 (t1, t0);

  return r;
}
#else
DECLSPEC u32x swap32 (const u32x v)
{
  return bitselect (rotate (v, 24u), rotate (v, 8u), 0x00ff00ffu);
}

DECLSPEC u64x swap64 (const u64x v)
{
  return bitselect (bitselect (rotate (v, 24ul),
                               rotate (v,  8ul), 0x000000ff000000fful),
                    bitselect (rotate (v, 56ul),
                               rotate (v, 40ul), 0x00ff000000ff0000ul),
                                                 0xffff0000ffff0000ul);
}
#endif

DECLSPEC u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64x rotr64 (const u64x a, const u32 n)
{
  const u32x a0 = h32_from_64 (a);
  const u32x a1 = l32_from_64 (a);

  const u32x t0 = (n >= 32) ? amd_bitalign (a0, a1, n - 32) : amd_bitalign (a1, a0, n);
  const u32x t1 = (n >= 32) ? amd_bitalign (a1, a0, n - 32) : amd_bitalign (a0, a1, n);

  const u64x r = hl32_to_64 (t0, t1);

  return r;
}

DECLSPEC u64x rotl64 (const u64x a, const u32 n)
{
  return rotr64 (a, 64 - n);
}

DECLSPEC u32x hc_bfe (const u32x a, const u32x b, const u32x c)
{
  return amd_bfe (a, b, c);
}

DECLSPEC u32 hc_bfe_S (const u32 a, const u32 b, const u32 c)
{
  return amd_bfe (a, b, c);
}

DECLSPEC u32x hc_bytealign (const u32x a, const u32x b, const u32x c)
{
  return amd_bytealign (a, b, c);
}

DECLSPEC u32 hc_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  return amd_bytealign (a, b, c);
}

#if AMD_GCN >= 3
DECLSPEC u32x hc_byte_perm (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));
  #endif

  #if VECT_SIZE >= 2
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  #endif

  #if VECT_SIZE >= 4
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  #endif

  #if VECT_SIZE >= 8
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s4) : "v"(b.s4), "v"(a.s4), "v"(c.s4));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s5) : "v"(b.s5), "v"(a.s5), "v"(c.s5));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s6) : "v"(b.s6), "v"(a.s6), "v"(c.s6));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s7) : "v"(b.s7), "v"(a.s7), "v"(c.s7));
  #endif

  #if VECT_SIZE >= 16
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s4) : "v"(b.s4), "v"(a.s4), "v"(c.s4));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s5) : "v"(b.s5), "v"(a.s5), "v"(c.s5));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s6) : "v"(b.s6), "v"(a.s6), "v"(c.s6));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s7) : "v"(b.s7), "v"(a.s7), "v"(c.s7));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s8) : "v"(b.s8), "v"(a.s8), "v"(c.s8));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.s9) : "v"(b.s9), "v"(a.s9), "v"(c.s9));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.sa) : "v"(b.sa), "v"(a.sa), "v"(c.sa));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.sb) : "v"(b.sb), "v"(a.sb), "v"(c.sb));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.sc) : "v"(b.sc), "v"(a.sc), "v"(c.sc));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.sd) : "v"(b.sd), "v"(a.sd), "v"(c.sd));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.se) : "v"(b.se), "v"(a.se), "v"(c.se));
  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r.sf) : "v"(b.sf), "v"(a.sf), "v"(c.sf));
  #endif

  return r;
}

DECLSPEC u32 hc_byte_perm_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  __asm__ ("V_PERM_B32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));

  return r;
}
#endif

#if AMD_GCN >= 5
DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));
  #endif

  #if VECT_SIZE >= 2
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  #endif

  #if VECT_SIZE >= 4
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  #endif

  #if VECT_SIZE >= 8
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s4) : "v"(b.s4), "v"(a.s4), "v"(c.s4));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s5) : "v"(b.s5), "v"(a.s5), "v"(c.s5));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s6) : "v"(b.s6), "v"(a.s6), "v"(c.s6));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s7) : "v"(b.s7), "v"(a.s7), "v"(c.s7));
  #endif

  #if VECT_SIZE >= 16
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s0) : "v"(b.s0), "v"(a.s0), "v"(c.s0));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s1) : "v"(b.s1), "v"(a.s1), "v"(c.s1));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s2) : "v"(b.s2), "v"(a.s2), "v"(c.s2));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s3) : "v"(b.s3), "v"(a.s3), "v"(c.s3));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s4) : "v"(b.s4), "v"(a.s4), "v"(c.s4));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s5) : "v"(b.s5), "v"(a.s5), "v"(c.s5));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s6) : "v"(b.s6), "v"(a.s6), "v"(c.s6));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s7) : "v"(b.s7), "v"(a.s7), "v"(c.s7));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s8) : "v"(b.s8), "v"(a.s8), "v"(c.s8));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.s9) : "v"(b.s9), "v"(a.s9), "v"(c.s9));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sa) : "v"(b.sa), "v"(a.sa), "v"(c.sa));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sb) : "v"(b.sb), "v"(a.sb), "v"(c.sb));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sc) : "v"(b.sc), "v"(a.sc), "v"(c.sc));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sd) : "v"(b.sd), "v"(a.sd), "v"(c.sd));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.se) : "v"(b.se), "v"(a.se), "v"(c.se));
  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r.sf) : "v"(b.sf), "v"(a.sf), "v"(c.sf));
  #endif

  return r;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  __asm__ ("V_ADD3_U32 %0, %1, %2, %3;" : "=v"(r) : "v"(b), "v"(a), "v"(c));

  return r;
}
#else
DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  return a + b + c;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  return a + b + c;
}
#endif

#endif

#ifdef IS_NV
DECLSPEC u32 swap32_S (const u32 v)
{
  u32 r;

  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r) : "r"(v));

  return r;
}

DECLSPEC u64 swap64_S (const u64 v)
{
  u32 il;
  u32 ir;

  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il), "=r"(ir) : "l"(v));

  u32 tl;
  u32 tr;

  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl) : "r"(il));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr) : "r"(ir));

  u64 r;

  asm ("mov.b64 %0, {%1, %2};" : "=l"(r) : "r"(tr), "r"(tl));

  return r;
}

DECLSPEC u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64 rotr64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) (64 - n));
}

DECLSPEC u64 rotl64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) n);
}

DECLSPEC u32x swap32 (const u32x v)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r) : "r"(v));
  #endif

  #if VECT_SIZE >= 2
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s0) : "r"(v.s0));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s1) : "r"(v.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s2) : "r"(v.s2));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s3) : "r"(v.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s4) : "r"(v.s4));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s5) : "r"(v.s5));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s6) : "r"(v.s6));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s7) : "r"(v.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s8) : "r"(v.s8));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.s9) : "r"(v.s9));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.sa) : "r"(v.sa));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.sb) : "r"(v.sb));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.sc) : "r"(v.sc));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.sd) : "r"(v.sd));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.se) : "r"(v.se));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r.sf) : "r"(v.sf));
  #endif

  return r;
}

DECLSPEC u64x swap64 (const u64x v)
{
  u32x il;
  u32x ir;

  #if VECT_SIZE == 1
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il), "=r"(ir) : "l"(v));
  #endif

  #if VECT_SIZE >= 2
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s0), "=r"(ir.s0) : "l"(v.s0));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s1), "=r"(ir.s1) : "l"(v.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s2), "=r"(ir.s2) : "l"(v.s2));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s3), "=r"(ir.s3) : "l"(v.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s4), "=r"(ir.s4) : "l"(v.s4));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s5), "=r"(ir.s5) : "l"(v.s5));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s6), "=r"(ir.s6) : "l"(v.s6));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s7), "=r"(ir.s7) : "l"(v.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s8), "=r"(ir.s8) : "l"(v.s8));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.s9), "=r"(ir.s9) : "l"(v.s9));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.sa), "=r"(ir.sa) : "l"(v.sa));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.sb), "=r"(ir.sb) : "l"(v.sb));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.sc), "=r"(ir.sc) : "l"(v.sc));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.sd), "=r"(ir.sd) : "l"(v.sd));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.se), "=r"(ir.se) : "l"(v.se));
  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il.sf), "=r"(ir.sf) : "l"(v.sf));
  #endif

  u32x tl;
  u32x tr;

  #if VECT_SIZE == 1
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl) : "r"(il));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr) : "r"(ir));
  #endif

  #if VECT_SIZE >= 2
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s0) : "r"(il.s0));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s0) : "r"(ir.s0));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s1) : "r"(il.s1));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s1) : "r"(ir.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s2) : "r"(il.s2));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s2) : "r"(ir.s2));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s3) : "r"(il.s3));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s3) : "r"(ir.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s4) : "r"(il.s4));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s4) : "r"(ir.s4));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s5) : "r"(il.s5));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s5) : "r"(ir.s5));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s6) : "r"(il.s6));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s6) : "r"(ir.s6));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s7) : "r"(il.s7));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s7) : "r"(ir.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s8) : "r"(il.s8));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s8) : "r"(ir.s8));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.s9) : "r"(il.s9));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.s9) : "r"(ir.s9));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.sa) : "r"(il.sa));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.sa) : "r"(ir.sa));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.sb) : "r"(il.sb));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.sb) : "r"(ir.sb));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.sc) : "r"(il.sc));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.sc) : "r"(ir.sc));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.sd) : "r"(il.sd));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.sd) : "r"(ir.sd));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.se) : "r"(il.se));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.se) : "r"(ir.se));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tl.sf) : "r"(il.sf));
  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(tr.sf) : "r"(ir.sf));
  #endif

  u64x r;

  #if VECT_SIZE == 1
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r) : "r"(tr), "r"(tl));
  #endif

  #if VECT_SIZE >= 2
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s0) : "r"(tr.s0), "r"(tl.s0));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s1) : "r"(tr.s1), "r"(tl.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s2) : "r"(tr.s2), "r"(tl.s2));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s3) : "r"(tr.s3), "r"(tl.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s4) : "r"(tr.s4), "r"(tl.s4));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s5) : "r"(tr.s5), "r"(tl.s5));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s6) : "r"(tr.s6), "r"(tl.s6));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s7) : "r"(tr.s7), "r"(tl.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s8) : "r"(tr.s8), "r"(tl.s8));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.s9) : "r"(tr.s9), "r"(tl.s9));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.sa) : "r"(tr.sa), "r"(tl.sa));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.sb) : "r"(tr.sb), "r"(tl.sb));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.sc) : "r"(tr.sc), "r"(tl.sc));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.sd) : "r"(tr.sd), "r"(tl.sd));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.se) : "r"(tr.se), "r"(tl.se));
  asm ("mov.b64 %0, {%1, %2};" : "=l"(r.sf) : "r"(tr.sf), "r"(tl.sf));
  #endif

  return r;
}

DECLSPEC u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64x rotr64 (const u64x a, const u32 n)
{
  return rotate (a, (u64x) (64 - n));
}

DECLSPEC u64x rotl64 (const u64x a, const u32 n)
{
  return rotate (a, (u64x) n);
}

DECLSPEC u32x hc_byte_perm (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r)    : "r"(a),    "r"(b),    "r"(c)   );
  #endif

  #if VECT_SIZE >= 2
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s0) : "r"(a.s0), "r"(b.s0), "r"(c.s0));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s1) : "r"(a.s1), "r"(b.s1), "r"(c.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s2) : "r"(a.s2), "r"(b.s2), "r"(c.s2));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s3) : "r"(a.s3), "r"(b.s3), "r"(c.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s4) : "r"(a.s4), "r"(b.s4), "r"(c.s4));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s5) : "r"(a.s5), "r"(b.s5), "r"(c.s5));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s6) : "r"(a.s6), "r"(b.s6), "r"(c.s6));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s7) : "r"(a.s7), "r"(b.s7), "r"(c.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s8) : "r"(a.s8), "r"(b.s8), "r"(c.s8));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.s9) : "r"(a.s9), "r"(b.s9), "r"(c.s9));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.sa) : "r"(a.sa), "r"(b.sa), "r"(c.sa));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.sb) : "r"(a.sb), "r"(b.sb), "r"(c.sb));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.sc) : "r"(a.sc), "r"(b.sc), "r"(c.sc));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.sd) : "r"(a.sd), "r"(b.sd), "r"(c.sd));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.se) : "r"(a.se), "r"(b.se), "r"(c.se));
  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r.sf) : "r"(a.sf), "r"(b.sf), "r"(c.sf));
  #endif

  return r;
}

DECLSPEC u32 hc_byte_perm_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

DECLSPEC u32x hc_bfe (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r)    : "r"(a),    "r"(b),    "r"(c));
  #endif

  #if VECT_SIZE >= 2
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s0) : "r"(a.s0), "r"(b.s0), "r"(c.s0));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s1) : "r"(a.s1), "r"(b.s1), "r"(c.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s2) : "r"(a.s2), "r"(b.s2), "r"(c.s2));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s3) : "r"(a.s3), "r"(b.s3), "r"(c.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s4) : "r"(a.s4), "r"(b.s4), "r"(c.s4));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s5) : "r"(a.s5), "r"(b.s5), "r"(c.s5));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s6) : "r"(a.s6), "r"(b.s6), "r"(c.s6));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s7) : "r"(a.s7), "r"(b.s7), "r"(c.s7));
  #endif

  #if VECT_SIZE >= 16
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s8) : "r"(a.s8), "r"(b.s8), "r"(c.s8));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.s9) : "r"(a.s9), "r"(b.s9), "r"(c.s9));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.sa) : "r"(a.sa), "r"(b.sa), "r"(c.sa));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.sb) : "r"(a.sb), "r"(b.sb), "r"(c.sb));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.sc) : "r"(a.sc), "r"(b.sc), "r"(c.sc));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.sd) : "r"(a.sd), "r"(b.sd), "r"(c.sd));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.se) : "r"(a.se), "r"(b.se), "r"(c.se));
  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r.sf) : "r"(a.sf), "r"(b.sf), "r"(c.sf));
  #endif

  return r;
}

DECLSPEC u32 hc_bfe_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

DECLSPEC u32x hc_bytealign (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if CUDA_ARCH >= 350

  #if VECT_SIZE == 1
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r)    : "r"(b),    "r"(a),    "r"((c & 3) * 8));
  #endif

  #if VECT_SIZE >= 2
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s0) : "r"(b.s0), "r"(a.s0), "r"((c.s0 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s1) : "r"(b.s1), "r"(a.s1), "r"((c.s1 & 3) * 8));
  #endif

  #if VECT_SIZE >= 4
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s2) : "r"(b.s2), "r"(a.s2), "r"((c.s2 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s3) : "r"(b.s3), "r"(a.s3), "r"((c.s3 & 3) * 8));
  #endif

  #if VECT_SIZE >= 8
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s4) : "r"(b.s4), "r"(a.s4), "r"((c.s4 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s5) : "r"(b.s5), "r"(a.s5), "r"((c.s5 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s6) : "r"(b.s6), "r"(a.s6), "r"((c.s6 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s7) : "r"(b.s7), "r"(a.s7), "r"((c.s7 & 3) * 8));
  #endif

  #if VECT_SIZE >= 16
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s8) : "r"(b.s8), "r"(a.s8), "r"((c.s8 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.s9) : "r"(b.s9), "r"(a.s9), "r"((c.s9 & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.sa) : "r"(b.sa), "r"(a.sa), "r"((c.sa & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.sb) : "r"(b.sb), "r"(a.sb), "r"((c.sb & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.sc) : "r"(b.sc), "r"(a.sc), "r"((c.sc & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.sd) : "r"(b.sd), "r"(a.sd), "r"((c.sd & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.se) : "r"(b.se), "r"(a.se), "r"((c.se & 3) * 8));
  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r.sf) : "r"(b.sf), "r"(a.sf), "r"((c.sf & 3) * 8));
  #endif

  #else

  r = hc_byte_perm (b, a, ((u32x) (0x76543210) >> ((c & 3) * 4)) & 0xffff);

  #endif

  return r;
}

DECLSPEC u32 hc_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  #if CUDA_ARCH >= 350

  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(b), "r"(a), "r"((c & 3) * 8));

  #else

  r = hc_byte_perm_S (b, a, (0x76543210 >> ((c & 3) * 4)) & 0xffff);

  #endif

  return r;
}

DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  return a + b + c;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  return a + b + c;
}

#endif

#ifdef IS_GENERIC
DECLSPEC u32 swap32_S (const u32 v)
{
  return (as_uint (as_uchar4 (v).s3210));
}

DECLSPEC u64 swap64_S (const u64 v)
{
  return (as_ulong (as_uchar8 (v).s76543210));
}

DECLSPEC u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64 rotr64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) (64 - n));
}

DECLSPEC u64 rotl64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) n);
}

DECLSPEC u32x swap32 (const u32x v)
{
  return ((v >> 24) & 0x000000ff)
       | ((v >>  8) & 0x0000ff00)
       | ((v <<  8) & 0x00ff0000)
       | ((v << 24) & 0xff000000);
}

DECLSPEC u64x swap64 (const u64x v)
{
  return ((v >> 56) & 0x00000000000000ff)
       | ((v >> 40) & 0x000000000000ff00)
       | ((v >> 24) & 0x0000000000ff0000)
       | ((v >>  8) & 0x00000000ff000000)
       | ((v <<  8) & 0x000000ff00000000)
       | ((v << 24) & 0x0000ff0000000000)
       | ((v << 40) & 0x00ff000000000000)
       | ((v << 56) & 0xff00000000000000);
}

DECLSPEC u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, (32 - n));
}

DECLSPEC u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

DECLSPEC u64x rotr64 (const u64x a, const u32 n)
{
  return rotate (a, (u64x) (64 - n));
}

DECLSPEC u64x rotl64 (const u64x a, const u32 n)
{
  return rotate (a, (u64x) n);
}

DECLSPEC u32x hc_bfe (const u32x a, const u32x b, const u32x c)
{
  #define BIT(x)      ((u32x) (1u) << (x))
  #define BIT_MASK(x) (BIT (x) - 1)
  #define BFE(x,y,z)  (((x) >> (y)) & BIT_MASK (z))

  return BFE (a, b, c);

  #undef BIT
  #undef BIT_MASK
  #undef BFE
}

DECLSPEC u32 hc_bfe_S (const u32 a, const u32 b, const u32 c)
{
  #define BIT(x)      (1u << (x))
  #define BIT_MASK(x) (BIT (x) - 1)
  #define BFE(x,y,z)  (((x) >> (y)) & BIT_MASK (z))

  return BFE (a, b, c);

  #undef BIT
  #undef BIT_MASK
  #undef BFE
}

DECLSPEC u32x hc_bytealign (const u32x a, const u32x b, const u32 c)
{
  #if VECT_SIZE == 1
  const u64x tmp = ((((u64x) (a)) << 32) | ((u64x) (b))) >> ((c & 3) * 8);

  return (u32x) (tmp);
  #endif

  #if VECT_SIZE == 2
  const u64x tmp = ((((u64x) (a.s0, a.s1)) << 32) | ((u64x) (b.s0, b.s1))) >> ((c & 3) * 8);

  return (u32x) (tmp.s0, tmp.s1);
  #endif

  #if VECT_SIZE == 4
  const u64x tmp = ((((u64x) (a.s0, a.s1, a.s2, a.s3)) << 32) | ((u64x) (b.s0, b.s1, b.s2, b.s3))) >> ((c & 3) * 8);

  return (u32x) (tmp.s0, tmp.s1, tmp.s2, tmp.s3);
  #endif

  #if VECT_SIZE == 8
  const u64x tmp = ((((u64x) (a.s0, a.s1, a.s2, a.s3, a.s4, a.s5, a.s6, a.s7)) << 32) | ((u64x) (b.s0, b.s1, b.s2, b.s3, b.s4, b.s5, b.s6, b.s7))) >> ((c & 3) * 8);

  return (u32x) (tmp.s0, tmp.s1, tmp.s2, tmp.s3, tmp.s4, tmp.s5, tmp.s6, tmp.s7);
  #endif

  #if VECT_SIZE == 16
  const u64x tmp = ((((u64x) (a.s0, a.s1, a.s2, a.s3, a.s4, a.s5, a.s6, a.s7, a.s8, a.s9, a.sa, a.sb, a.sc, a.sd, a.se, a.sf)) << 32) | ((u64x) (b.s0, b.s1, b.s2, b.s3, b.s4, b.s5, b.s6, b.s7, b.s8, b.s9, b.sa, b.sb, b.sc, b.sd, b.se, b.sf))) >> ((c & 3) * 8);

  return (u32x) (tmp.s0, tmp.s1, tmp.s2, tmp.s3, tmp.s4, tmp.s5, tmp.s6, tmp.s7, tmp.s8, tmp.s9, tmp.sa, tmp.sb, tmp.sc, tmp.sd, tmp.se, tmp.sf);
  #endif
}

DECLSPEC u32 hc_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  const u64 tmp = ((((u64) a) << 32) | ((u64) b)) >> ((c & 3) * 8);

  return (u32) (tmp);
}

DECLSPEC u32x hc_add3 (const u32x a, const u32x b, const u32x c)
{
  return a + b + c;
}

DECLSPEC u32 hc_add3_S (const u32 a, const u32 b, const u32 c)
{
  return a + b + c;
}

#endif

typedef struct digest
{
  u32 digest_buf[DGST_ELEM];

} digest_t;

typedef struct salt
{
  u32 salt_buf[64];
  u32 salt_buf_pc[64];

  u32 salt_len;
  u32 salt_len_pc;
  u32 salt_iter;
  u32 salt_iter2;
  u32 salt_sign[2];

  u32 digests_cnt;
  u32 digests_done;

  u32 digests_offset;

  u32 scrypt_N;
  u32 scrypt_r;
  u32 scrypt_p;

} salt_t;

#define LUKS_STRIPES 4000

typedef enum hc_luks_hash_type
{
  HC_LUKS_HASH_TYPE_SHA1      = 1,
  HC_LUKS_HASH_TYPE_SHA256    = 2,
  HC_LUKS_HASH_TYPE_SHA512    = 3,
  HC_LUKS_HASH_TYPE_RIPEMD160 = 4,
  HC_LUKS_HASH_TYPE_WHIRLPOOL = 5,

} hc_luks_hash_type_t;

typedef enum hc_luks_key_size
{
  HC_LUKS_KEY_SIZE_128 = 128,
  HC_LUKS_KEY_SIZE_256 = 256,
  HC_LUKS_KEY_SIZE_512 = 512,

} hc_luks_key_size_t;

typedef enum hc_luks_cipher_type
{
  HC_LUKS_CIPHER_TYPE_AES     = 1,
  HC_LUKS_CIPHER_TYPE_SERPENT = 2,
  HC_LUKS_CIPHER_TYPE_TWOFISH = 3,

} hc_luks_cipher_type_t;

typedef enum hc_luks_cipher_mode
{
  HC_LUKS_CIPHER_MODE_CBC_ESSIV = 1,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN = 2,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN = 3,

} hc_luks_cipher_mode_t;

typedef struct luks
{
  int hash_type;    // hc_luks_hash_type_t
  int key_size;     // hc_luks_key_size_t
  int cipher_type;  // hc_luks_cipher_type_t
  int cipher_mode;  // hc_luks_cipher_mode_t

  u32 ct_buf[128];

  u32 af_src_buf[((HC_LUKS_KEY_SIZE_512 / 8) * LUKS_STRIPES) / 4];

} luks_t;

typedef struct itunes_backup
{
  u32 wpky[10];
  u32 dpsl[5];

} itunes_backup_t;

typedef struct blake2
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u32 buflen;
  u32 outlen;

} blake2_t;

typedef struct chacha20
{
  u32 iv[2];
  u32 plain[2];
  u32 position[2];
  u32 offset;

} chacha20_t;

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

typedef struct wpa_eapol
{
  u32  pke[32];
  u32  eapol[64 + 16];
  u16  eapol_len;
  u8   message_pair;
  int  message_pair_chgd;
  u8   keyver;
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   orig_nonce_ap[32];
  u8   orig_nonce_sta[32];
  u8   essid_len;
  u8   essid[32];
  u32  keymic[4];
  u32  hash[4];
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

typedef struct wpa_pmkid
{
  u32  pmkid[4];
  u32  pmkid_data[16];
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   essid_len;
  u32  essid_buf[16];

} wpa_pmkid_t;

typedef struct bitcoin_wallet
{
  u32 cry_master_buf[64];
  u32 ckey_buf[64];
  u32 public_key_buf[64];

  u32 cry_master_len;
  u32 ckey_len;
  u32 public_key_len;

} bitcoin_wallet_t;

typedef struct sip
{
  u32 salt_buf[32];
  u32 salt_len;

  u32 esalt_buf[256];
  u32 esalt_len;

} sip_t;

typedef struct androidfde
{
  u32 data[384];

} androidfde_t;

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len[6];

} ikepsk_t;

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

typedef struct krb5pa
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

typedef struct krb5tgs
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_t;

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5asrep_t;

typedef struct keyboard_layout_mapping
{
  u32 src_char;
  int src_len;
  u32 dst_char;
  int dst_len;

} keyboard_layout_mapping_t;

typedef struct tc
{
  u32 salt_buf[32];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

} tc_t;

typedef struct pbkdf2_md5
{
  u32 salt_buf[16];

} pbkdf2_md5_t;

typedef struct pbkdf2_sha1
{
  u32 salt_buf[16];

} pbkdf2_sha1_t;

typedef struct pbkdf2_sha256
{
  u32 salt_buf[16];

} pbkdf2_sha256_t;

typedef struct pbkdf2_sha512
{
  u32 salt_buf[32];

} pbkdf2_sha512_t;

typedef struct rakp
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

typedef struct cloudkey
{
  u32 data_len;
  u32 data_buf[512];

} cloudkey_t;

typedef struct office2007
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];

  u32 keySize;

} office2007_t;

typedef struct office2010
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2010_t;

typedef struct office2013
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2013_t;

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 rc4key[2];

} oldoffice34_t;

typedef struct odf11_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[5];
  u32  out[5];

} odf11_tmp_t;

typedef struct odf11
{
  u32 iterations;
  u32 iv[2];
  u32 checksum[5];
  u32 encrypted_data[256];

} odf11_t;

typedef struct odf12_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} odf12_tmp_t;

typedef struct odf12
{
  u32 iterations;
  u32 iv[4];
  u32 checksum[8];
  u32 encrypted_data[256];

} odf12_t;

typedef struct pstoken
{
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

typedef struct zip2
{
  u32 type;
  u32 mode;
  u32 magic;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 compress_length;
  u32 data_len;
  u32 data_buf[2048];
  u32 auth_len;
  u32 auth_buf[4];

} zip2_t;

typedef struct win8phone
{
  u32 salt_buf[32];

} win8phone_t;

typedef struct keepass
{
  u32 version;
  u32 algorithm;

  /* key-file handling */
  u32 keyfile_len;
  u32 keyfile[8];

  u32 final_random_seed[8];
  u32 transf_random_seed[8];
  u32 enc_iv[4];
  u32 contents_hash[8];

  /* specific to version 1 */
  u32 contents_len;
  u32 contents[75000];

  /* specific to version 2 */
  u32 expected_bytes[8];

} keepass_t;

typedef struct dpapimk
{
  u32 context;

  u32 SID[32];
  u32 SID_len;
  u32 SID_offset;

  /* here only for possible
     forward compatibiliy
  */
  // u8 cipher_algo[16];
  // u8 hash_algo[16];

  u32 iv[4];
  u32 contents_len;
  u32 contents[128];

} dpapimk_t;

typedef struct jks_sha1
{
  u32 checksum[5];
  u32 iv[5];
  u32 enc_key_buf[4096];
  u32 enc_key_len;
  u32 der[5];
  u32 alias[16];

} jks_sha1_t;

typedef struct ethereum_pbkdf2
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_pbkdf2_t;

typedef struct ethereum_scrypt
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_scrypt_t;

typedef struct ethereum_presale
{
  u32 iv[4];
  u32 enc_seed[152];
  u32 enc_seed_len;

} ethereum_presale_t;

typedef struct tacacs_plus
{
  u32 session_buf[16];

  u32 ct_data_buf[64];
  u32 ct_data_len;

  u32 sequence_buf[16];

} tacacs_plus_t;

typedef struct apple_secure_notes
{
  u32 Z_PK;
  u32 ZCRYPTOITERATIONCOUNT;
  u32 ZCRYPTOSALT[16];
  u32 ZCRYPTOWRAPPEDKEY[16];

} apple_secure_notes_t;

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

} jwt_t;

typedef struct electrum_wallet
{
  u32 salt_type;
  u32 iv[4];
  u32 encrypted[4];

} electrum_wallet_t;

typedef struct ansible_vault
{
  u32 cipher;
  u32 version;
  u32 ct_data_buf[4096];
  u32 ct_data_len;
} ansible_vault_t;

typedef struct pdf14_tmp
{
  u32 digest[4];
  u32 out[4];

} pdf14_tmp_t;

typedef struct luks_tmp
{
  u32 ipad32[8];
  u64 ipad64[8];

  u32 opad32[8];
  u64 opad64[8];

  u32 dgst32[32];
  u64 dgst64[16];

  u32 out32[32];
  u64 out64[16];

} luks_tmp_t;

typedef struct pdf17l8_tmp
{
  union
  {
    u32 dgst32[16];
    u64 dgst64[8];
  };

  u32 dgst_len;
  u32 W_len;

} pdf17l8_tmp_t;

typedef struct phpass_tmp
{
  u32 digest_buf[4];

} phpass_tmp_t;

typedef struct md5crypt_tmp
{
  u32 digest_buf[4];

} md5crypt_tmp_t;

typedef struct sha256crypt_tmp
{
  // pure version

  u32 alt_result[8];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha256crypt_tmp_t;

typedef struct sha512crypt_tmp
{
  u64 l_alt_result[8];
  u64 l_p_bytes[2];
  u64 l_s_bytes[2];

  // pure version

  u32 alt_result[16];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha512crypt_tmp_t;

typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_pbkdf2_tmp_t;

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

typedef struct bitcoin_wallet_tmp
{
  u64  dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct dcc2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[4];

} dcc2_tmp_t;

typedef struct bcrypt_tmp
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

typedef struct pwsafe2_tmp
{
  u32 digest[2];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} pwsafe2_tmp_t;

typedef struct pwsafe3_tmp
{
  u32 digest_buf[8];

} pwsafe3_tmp_t;

typedef struct androidpin_tmp
{
  u32 digest_buf[5];

} androidpin_tmp_t;

typedef struct androidfde_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} androidfde_tmp_t;

typedef struct tc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

typedef struct tc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} tc64_tmp_t;

typedef struct vc64_sbog_tmp
{
  u64  ipad_raw[8];
  u64  opad_raw[8];

  u64  ipad_hash[8];
  u64  opad_hash[8];

  u64  dgst[32];
  u64  out[32];

} vc64_sbog_tmp_t;

typedef struct pbkdf1_sha1_tmp
{
  // pbkdf1-sha1 is limited to 160 bits

  u32  ipad[5];
  u32  opad[5];

  u32  out[5];

} pbkdf1_sha1_tmp_t;

typedef struct pbkdf2_md5_tmp
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

typedef struct ecryptfs_tmp
{
  u64  out[8];

} ecryptfs_tmp_t;

typedef struct oraclet_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} oraclet_tmp_t;

typedef struct agilekey_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} agilekey_tmp_t;

typedef struct mywallet_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} mywallet_tmp_t;

typedef struct sha1aix_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} sha1aix_tmp_t;

typedef struct sha256aix_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} sha256aix_tmp_t;

typedef struct sha512aix_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} sha512aix_tmp_t;

typedef struct lastpass_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} lastpass_tmp_t;

typedef struct drupal7_tmp
{
  u64  digest_buf[8];

} drupal7_tmp_t;

typedef struct lotus8_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} lotus8_tmp_t;

typedef struct office2007_tmp
{
  u32 out[5];

} office2007_tmp_t;

typedef struct office2010_tmp
{
  u32 out[5];

} office2010_tmp_t;

typedef struct office2013_tmp
{
  u64  out[8];

} office2013_tmp_t;

typedef struct saph_sha1_tmp
{
  u32 digest_buf[5];

} saph_sha1_tmp_t;

typedef struct seven_zip_tmp
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} seven_zip_tmp_t;

typedef struct axcrypt_tmp
{
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct keepass_tmp
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct dpapimk_tmp_v1
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

  u32 userKey[5];

} dpapimk_tmp_v1_t;

typedef struct dpapimk_tmp_v2
{
  u64 ipad64[8];
  u64 opad64[8];
  u64 dgst64[16];
  u64 out64[16];

  u32 userKey[8];

} dpapimk_tmp_v2_t;

typedef struct apple_secure_notes_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} apple_secure_notes_tmp_t;

typedef struct bsdicrypt_tmp
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

typedef struct rar3_tmp
{
  u32 dgst[17][5];

} rar3_tmp_t;

typedef struct
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

typedef struct cram_md5
{
  u32 user[16];

} cram_md5_t;

typedef struct
{
  u32 key;
  u64 val;

} hcstat_table_t;

typedef struct
{
  u32 cs_buf[0x100];
  u32 cs_len;

} cs_t;

typedef struct
{
  u32 cmds[32];

} kernel_rule_t;

typedef struct pw
{
  u32 i[64];

  u32 pw_len;

} pw_t;

typedef struct pw_idx
{
  u32 off;
  u32 cnt;
  u32 len;

} pw_idx_t;

typedef struct bf
{
  u32  i;

} bf_t;

typedef struct bs_word
{
  u32  b[32];

} bs_word_t;

typedef struct plain
{
  u64  gidvid;
  u32  il_pos;
  u32  salt_pos;
  u32  digest_pos;
  u32  hash_pos;

} plain_t;

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  uint4 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

typedef enum combinator_mode
{
  COMBINATOR_MODE_BASE_LEFT  = 10001,
  COMBINATOR_MODE_BASE_RIGHT = 10002

} combinator_mode_t;
