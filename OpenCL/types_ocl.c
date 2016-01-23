/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define DEVICE_TYPE_CPU 2
#define DEVICE_TYPE_GPU 4

typedef uchar  u8;
typedef ushort u16;
typedef uint   u32;
typedef ulong  u64;

#ifndef NEW_SIMD_CODE
#undef  VECT_SIZE
#define VECT_SIZE 1
#endif

#if VECT_SIZE == 1
typedef uchar   u8x;
typedef ushort  u16x;
typedef uint    u32x;
typedef ulong   u64x;
#endif

#if VECT_SIZE == 2
typedef uchar2  u8x;
typedef ushort2 u16x;
typedef uint2   u32x;
typedef ulong2  u64x;
#endif

#if VECT_SIZE == 4
typedef uchar4  u8x;
typedef ushort4 u16x;
typedef uint4   u32x;
typedef ulong4  u64x;
#endif

#if VECT_SIZE == 8
typedef uchar8  u8x;
typedef ushort8 u16x;
typedef uint8   u32x;
typedef ulong8  u64x;
#endif

// this one needs to die
#define allx(r) r

static inline u32 l32_from_64_S (u64 a)
{
  const u32 r = (u32) (a);

  return r;
}

static inline u32 h32_from_64_S (u64 a)
{
  a >>= 32;

  const u32 r = (u32) (a);

  return r;
}

static inline u64 hl32_to_64_S (const u32 a, const u32 b)
{
  return as_ulong ((uint2) (b, a));
}

static inline u32x l32_from_64 (u64x a)
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

  return r;
}

static inline u32x h32_from_64 (u64x a)
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

  return r;
}

static inline u64x hl32_to_64 (const u32x a, const u32x b)
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

  return r;
}

#ifdef IS_AMD
static inline u32 swap32_S (const u32 v)
{
  return (as_uint (as_uchar4 (v).s3210));
}

static inline u64 swap64_S (const u64 v)
{
  return (as_ulong (as_uchar8 (v).s76543210));
}

static inline u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

static inline u64 rotr64_S (const u64 a, const u32 n)
{
  u64 r;

  #if DEVICE_TYPE == DEVICE_TYPE_CPU

  r = rotate (a, (u64) 64 - n);

  #else

  uint2 a2 = as_uint2 (a);

  uint2 t;

  t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32)
                   : amd_bitalign (a2.s1, a2.s0, n);
  t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32)
                   : amd_bitalign (a2.s0, a2.s1, n);

  r = as_ulong (t);

  #endif

  return r;
}

static inline u64 rotl64_S (const u64 a, const u32 n)
{
  return rotr64_S (a, 64 - n);
}

static inline u32x swap32 (const u32x v)
{
  return ((v >> 24) & 0x000000ff)
       | ((v >>  8) & 0x0000ff00)
       | ((v <<  8) & 0x00ff0000)
       | ((v << 24) & 0xff000000);
}

static inline u64x swap64 (const u64x v)
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

static inline u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

static inline u64x rotr64 (const u64x a, const u32 n)
{
  u64x r;

  #if DEVICE_TYPE == DEVICE_TYPE_CPU

  r = rotate (a, (u64) 64 - n);

  #else

  uint2 a2;
  uint2 t;

  #if   VECT_SIZE == 1

  a2 = as_uint2 (a);

  t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
  t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

  r = as_ulong (t);

  #elif VECT_SIZE == 2

  {
    a2 = as_uint2 (a.s0);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s0 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s1);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s1 = as_ulong (t);
  }

  #elif VECT_SIZE == 4

  {
    a2 = as_uint2 (a.s0);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s0 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s1);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s1 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s2);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s2 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s3);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s3 = as_ulong (t);
  }

  #elif VECT_SIZE == 8

  {
    a2 = as_uint2 (a.s0);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s0 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s1);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s1 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s2);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s2 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s3);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s3 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s4);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s4 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s5);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s5 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s6);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s6 = as_ulong (t);
  }

  {
    a2 = as_uint2 (a.s7);

    t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32) : amd_bitalign (a2.s1, a2.s0, n);
    t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32) : amd_bitalign (a2.s0, a2.s1, n);

    r.s7 = as_ulong (t);
  }

  #endif
  #endif

  return r;
}

static inline u64x rotl64 (const u64x a, const u32 n)
{
  return rotr64 (a, 64 - n);
}

static inline u32 __bfe (const u32 a, const u32 b, const u32 c)
{
  return amd_bfe (a, b, c);
}

static inline u32 amd_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  return amd_bytealign (a, b, c);
}
#endif

#ifdef IS_NV
static inline u32 swap32_S (const u32 v)
{
  u32 r;

  asm ("prmt.b32 %0, %1, 0, 0x0123;" : "=r"(r) : "r"(v));

  return r;
}

static inline u64 swap64_S (const u64 v)
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

static inline u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

#if CUDA_ARCH >= 350
static inline u64 rotr64_S (const u64 a, const u32 n)
{
  u32 il;
  u32 ir;

  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il), "=r"(ir) : "l"(a));

  u32 tl;
  u32 tr;

  if (n >= 32)
  {
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tl) : "r"(ir), "r"(il), "r"(n - 32));
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tr) : "r"(il), "r"(ir), "r"(n - 32));
  }
  else
  {
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tl) : "r"(il), "r"(ir), "r"(n));
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tr) : "r"(ir), "r"(il), "r"(n));
  }

  u64 r;

  asm ("mov.b64 %0, {%1, %2};" : "=l"(r) : "r"(tl), "r"(tr));

  return r;
}
#else
static inline u64 rotr64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) 64 - n);
}
#endif

static inline u64 rotl64_S (const u64 a, const u32 n)
{
  return rotr64_S (a, 64 - n);
}

#if CUDA_ARCH >= 500
static inline u32 lut3_2d_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_39_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_59_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_96_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_e4_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_e8_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_ca_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}
#endif

static inline u32 __byte_perm_S (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

static inline u32x swap32 (const u32x v)
{
  return ((v >> 24) & 0x000000ff)
       | ((v >>  8) & 0x0000ff00)
       | ((v <<  8) & 0x00ff0000)
       | ((v << 24) & 0xff000000);
}

static inline u64x swap64 (const u64x v)
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

static inline u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

static inline u64x rotr64 (const u64x a, const u32 n)
{
  return rotate (a, (u64) 64 - n);
}

static inline u64x rotl64 (const u64x a, const u32 n)
{
  return rotate (a, (u64) n);
}

static inline u32x __byte_perm (const u32x a, const u32x b, const u32x c)
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

  return r;
}

static inline u32 __bfe (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

#if CUDA_ARCH >= 350
static inline u32 amd_bytealign (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(b), "r"(a), "r"((c & 3) * 8));

  return r;
}
#else
static inline u32 amd_bytealign (const u32 a, const u32 b, const u32 c)
{
  return __byte_perm_S (b, a, (0x76543210 >> ((c & 3) * 4)) & 0xffff);
}
#endif

#if CUDA_ARCH >= 500
static inline u32x lut3_2d (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r) : "r" (a), "r" (b), "r" (c));
  #endif

  #if VECT_SIZE >= 2
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE >= 4
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE >= 8
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_39 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r) : "r" (a), "r" (b), "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_59 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r) : "r" (a), "r" (b), "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_96 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r)    : "r" (a),    "r" (b),    "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_e4 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r)    : "r" (a),    "r" (b),    "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_e8 (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r)    : "r" (a),    "r" (b),    "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

static inline u32x lut3_ca (const u32x a, const u32x b, const u32x c)
{
  u32x r;

  #if VECT_SIZE == 1
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r)    : "r" (a),    "r" (b),    "r" (c));
  #endif

  #if VECT_SIZE == 2
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  #endif

  #if VECT_SIZE == 4
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  #endif

  #if VECT_SIZE == 8
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s0) : "r" (a.s0), "r" (b.s0), "r" (c.s0));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s1) : "r" (a.s1), "r" (b.s1), "r" (c.s1));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s2) : "r" (a.s2), "r" (b.s2), "r" (c.s2));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s3) : "r" (a.s3), "r" (b.s3), "r" (c.s3));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s4) : "r" (a.s4), "r" (b.s4), "r" (c.s4));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s5) : "r" (a.s5), "r" (b.s5), "r" (c.s5));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s6) : "r" (a.s6), "r" (b.s6), "r" (c.s6));
  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r.s7) : "r" (a.s7), "r" (b.s7), "r" (c.s7));
  #endif

  return r;
}

#endif
#endif

#ifdef IS_GENERIC
static inline u32 swap32_S (const u32 v)
{
  return (as_uint (as_uchar4 (v).s3210));
}

static inline u64 swap64_S (const u64 v)
{
  return (as_ulong (as_uchar8 (v).s76543210));
}

static inline u32 rotr32_S (const u32 a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32 rotl32_S (const u32 a, const u32 n)
{
  return rotate (a, n);
}

static inline u64 rotr64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) 64 - n);
}

static inline u64 rotl64_S (const u64 a, const u32 n)
{
  return rotate (a, (u64) n);
}

static inline u32 amd_bytealign_S (const u32 a, const u32 b, const u32 c)
{
  const u64 tmp = ((((u64) a) << 32) | ((u64) b)) >> ((c & 3) * 8);

  return (u32) (tmp);
}

static inline u32x swap32 (const u32x v)
{
  return ((v >> 24) & 0x000000ff)
       | ((v >>  8) & 0x0000ff00)
       | ((v <<  8) & 0x00ff0000)
       | ((v << 24) & 0xff000000);
}

static inline u64x swap64 (const u64x v)
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

static inline u32x rotr32 (const u32x a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32x rotl32 (const u32x a, const u32 n)
{
  return rotate (a, n);
}

static inline u64x rotr64 (const u64x a, const u32 n)
{
  return rotate (a, (u64) 64 - n);
}

static inline u64x rotl64 (const u64x a, const u32 n)
{
  return rotate (a, (u64) n);
}

static inline u32 __bfe (const u32 a, const u32 b, const u32 c)
{
  #define BIT(x)      (1 << (x))
  #define BIT_MASK(x) (BIT (x) - 1)
  #define BFE(x,y,z)  (((x) >> (y)) & BIT_MASK (z))

  return BFE (a, b, c);
}

static inline u32x amd_bytealign (const u32x a, const u32x b, const u32 c)
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
}
#endif

typedef struct
{
  #if   defined _DES_
  u32  digest_buf[4];
  #elif defined _MD4_
  u32  digest_buf[4];
  #elif defined _MD5_
  u32  digest_buf[4];
  #elif defined _MD5H_
  u32  digest_buf[4];
  #elif defined _SHA1_
  u32  digest_buf[5];
  #elif defined _BCRYPT_
  u32  digest_buf[6];
  #elif defined _SHA256_
  u32  digest_buf[8];
  #elif defined _SHA384_
  u32  digest_buf[16];
  #elif defined _SHA512_
  u32  digest_buf[16];
  #elif defined _KECCAK_
  u32  digest_buf[50];
  #elif defined _RIPEMD160_
  u32  digest_buf[5];
  #elif defined _WHIRLPOOL_
  u32  digest_buf[16];
  #elif defined _GOST_
  u32  digest_buf[8];
  #elif defined _GOST2012_256_
  u32  digest_buf[8];
  #elif defined _GOST2012_512_
  u32  digest_buf[16];
  #elif defined _SAPB_
  u32  digest_buf[4];
  #elif defined _SAPG_
  u32  digest_buf[5];
  #elif defined _MYSQL323_
  u32  digest_buf[4];
  #elif defined _LOTUS5_
  u32  digest_buf[4];
  #elif defined _LOTUS6_
  u32  digest_buf[4];
  #elif defined _SCRYPT_
  u32  digest_buf[8];
  #elif defined _LOTUS8_
  u32  digest_buf[4];
  #elif defined _OFFICE2007_
  u32  digest_buf[4];
  #elif defined _OFFICE2010_
  u32  digest_buf[4];
  #elif defined _OFFICE2013_
  u32  digest_buf[4];
  #elif defined _OLDOFFICE01_
  u32  digest_buf[4];
  #elif defined _OLDOFFICE34_
  u32  digest_buf[4];
  #elif defined _SIPHASH_
  u32  digest_buf[4];
  #elif defined _PBKDF2_MD5_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA1_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA256_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA512_
  u32  digest_buf[32];
  #elif defined _PDF17L8_
  u32  digest_buf[8];
  #elif defined _CRC32_
  u32  digest_buf[4];
  #elif defined _SEVEN_ZIP_
  u32  digest_buf[4];
  #elif defined _ANDROIDFDE_
  u32  digest_buf[4];
  #elif defined _DCC2_
  u32  digest_buf[4];
  #elif defined _WPA_
  u32  digest_buf[4];
  #elif defined _MD5_SHA1_
  u32  digest_buf[4];
  #elif defined _SHA1_MD5_
  u32  digest_buf[5];
  #elif defined _NETNTLMV2_
  u32  digest_buf[4];
  #elif defined _KRB5PA_
  u32  digest_buf[4];
  #elif defined _CLOUDKEY_
  u32  digest_buf[8];
  #elif defined _SCRYPT_
  u32  digest_buf[4];
  #elif defined _PSAFE2_
  u32  digest_buf[5];
  #elif defined _LOTUS8_
  u32  digest_buf[4];
  #elif defined _RAR3_
  u32  digest_buf[4];
  #elif defined _SHA256_SHA1_
  u32  digest_buf[8];
  #elif defined _MS_DRSR_
  u32  digest_buf[8];
  #elif defined _ANDROIDFDE_SAMSUNG_
  u32  digest_buf[8];
  #elif defined _RAR5_
  u32  digest_buf[4];
  #endif

} digest_t;

typedef struct
{
  u32 salt_buf[16];
  u32 salt_buf_pc[8];

  u32 salt_len;
  u32 salt_iter;
  u32 salt_sign[2];

  u32 keccak_mdlen;
  u32 truecrypt_mdlen;

  u32 digests_cnt;
  u32 digests_done;

  u32 digests_offset;

  u32 scrypt_N;
  u32 scrypt_r;
  u32 scrypt_p;
  u32 scrypt_tmto;
  u32 scrypt_phy;

} salt_t;

typedef struct
{
  int V;
  int R;
  int P;

  int enc_md;

  u32 id_buf[8];
  u32 u_buf[32];
  u32 o_buf[32];

  int id_len;
  int o_len;
  int u_len;

  u32 rc4key[2];
  u32 rc4data[2];

} pdf_t;

typedef struct
{
  u32 pke[25];
  u32 eapol[64];
  int eapol_size;
  int keyver;

} wpa_t;

typedef struct
{
  u32 cry_master_buf[64];
  u32 ckey_buf[64];
  u32 public_key_buf[64];

  u32 cry_master_len;
  u32 ckey_len;
  u32 public_key_len;

} bitcoin_wallet_t;

typedef struct
{
  u32 salt_buf[30];
  u32 salt_len;

  u32 esalt_buf[38];
  u32 esalt_len;

} sip_t;

typedef struct
{
  u32 data[384];

} androidfde_t;

typedef struct
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len;

} ikepsk_t;

typedef struct
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

typedef struct
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

typedef struct
{
  u32 salt_buf[16];
  u32 data_buf[112];
  u32 keyfile_buf[16];

} tc_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_md5_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_sha1_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_sha256_t;

typedef struct
{
  u32 salt_buf[32];

} pbkdf2_sha512_t;

typedef struct
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

typedef struct
{
  u32 data_len;
  u32 data_buf[512];

} cloudkey_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];

  u32 keySize;

} office2007_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2010_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2013_t;

typedef struct
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

typedef struct
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 rc4key[2];

} oldoffice34_t;

typedef struct
{
  u32 digest[4];
  u32 out[4];

} pdf14_tmp_t;

typedef struct
{
  union
  {
    u32 dgst32[16];
    u64 dgst64[8];
  };

  u32 dgst_len;
  u32 W_len;

} pdf17l8_tmp_t;

typedef struct
{
  u32 digest_buf[4];

} phpass_tmp_t;

typedef struct
{
  u32 digest_buf[4];

} md5crypt_tmp_t;

typedef struct
{
  u32 alt_result[8];

  u32 p_bytes[4];
  u32 s_bytes[4];

} sha256crypt_tmp_t;

typedef struct
{
  u64 l_alt_result[8];

  u64 l_p_bytes[2];
  u64 l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_tmp_t;

typedef struct
{
  u64 dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[4];

} dcc2_tmp_t;

typedef struct
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

typedef struct
{
  u32 digest[2];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} pwsafe2_tmp_t;

typedef struct
{
  u32 digest_buf[8];

} pwsafe3_tmp_t;

typedef struct
{
  u32 digest_buf[5];

} androidpin_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} androidfde_tmp_t;

typedef struct
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[32];
  u64 out[32];

} tc64_tmp_t;

typedef struct
{
  u32 ipad[4];
  u32 opad[4];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  u64 out[8];

} ecryptfs_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

} oraclet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} agilekey_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst1[5];
  u32 out1[5];

  u32 dgst2[5];
  u32 out2[5];

} mywallet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} sha1aix_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} sha256aix_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

} sha512aix_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} lastpass_tmp_t;

typedef struct
{
  u64 digest_buf[8];

} drupal7_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} lotus8_tmp_t;

typedef struct
{
  u32 out[5];

} office2007_tmp_t;

typedef struct
{
  u32 out[5];

} office2010_tmp_t;

typedef struct
{
  u64 out[8];

} office2013_tmp_t;

typedef struct
{
  u32 digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  u32 block[16];

  u32 dgst[8];

  u32 block_len;
  u32 final_len;

} seven_zip_tmp_t;

typedef struct
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

typedef struct
{
  u32 dgst[17][5];

} rar3_tmp_t;

typedef struct
{
  u32 user[16];

} cram_md5_t;

typedef struct
{
  u32 iv_buf[4];
  u32 iv_len;

  u32 salt_buf[4];
  u32 salt_len;

  u32 crc;

  u32 data_buf[96];
  u32 data_len;

  u32 unpack_size;

} seven_zip_t;

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
  u32 cmds[0x100];

} kernel_rule_t;

typedef struct
{
  u32 gidvid;
  u32 il_pos;

} plain_t;

typedef struct
{
  u32 i[64];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct
{
  u32 i;

} bf_t;

typedef struct
{
  u32 i[8];

  u32 pw_len;

} comb_t;

typedef struct
{
  u32 b[32];

} bs_word_t;

typedef struct
{
  uint4 P[64];

} scrypt_tmp_t;
