/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_TYPES_H
#define _INC_TYPES_H

#if ATTACK_MODE == 9
#define BITMAP_MASK         kernel_param->bitmap_mask
#define BITMAP_SHIFT1       kernel_param->bitmap_shift1
#define BITMAP_SHIFT2       kernel_param->bitmap_shift2
#define SALT_POS_HOST       (kernel_param->pws_pos + gid)
#define LOOP_POS            kernel_param->loop_pos
#define LOOP_CNT            kernel_param->loop_cnt
#define IL_CNT              kernel_param->il_cnt
#define DIGESTS_CNT         1
#define DIGESTS_OFFSET_HOST (kernel_param->pws_pos + gid)
#define COMBS_MODE          kernel_param->combs_mode
#define SALT_REPEAT         kernel_param->salt_repeat
#define PWS_POS             kernel_param->pws_pos
#define GID_CNT             kernel_param->gid_max
#else
#define BITMAP_MASK         kernel_param->bitmap_mask
#define BITMAP_SHIFT1       kernel_param->bitmap_shift1
#define BITMAP_SHIFT2       kernel_param->bitmap_shift2
#define SALT_POS_HOST       kernel_param->salt_pos_host
#define LOOP_POS            kernel_param->loop_pos
#define LOOP_CNT            kernel_param->loop_cnt
#define IL_CNT              kernel_param->il_cnt
#define DIGESTS_CNT         kernel_param->digests_cnt
#define DIGESTS_OFFSET_HOST kernel_param->digests_offset_host
#define COMBS_MODE          kernel_param->combs_mode
#define SALT_REPEAT         kernel_param->salt_repeat
#define PWS_POS             kernel_param->pws_pos
#define GID_CNT             kernel_param->gid_max
#endif

#ifdef IS_CUDA
// https://docs.nvidia.com/cuda/nvrtc/index.html#integer-size
typedef unsigned char       uchar;
typedef unsigned short      ushort;
typedef unsigned int        uint;
typedef unsigned long       ulong;
typedef unsigned long long  ullong;
#endif

#ifdef IS_METAL
typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
typedef unsigned long  ulong;
#define ullong ulong
#endif

#ifdef IS_OPENCL
typedef ulong   ullong;
typedef ulong2  ullong2;
typedef ulong4  ullong4;
typedef ulong8  ullong8;
typedef ulong16 ullong16;
#endif

#ifdef KERNEL_STATIC
typedef uchar  u8;
typedef ushort u16;
typedef uint   u32;
#ifdef IS_METAL
typedef ulong  u64;
#else
typedef ullong u64;
#endif
#else
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

//testwise disabled
//typedef u8  u8a  __attribute__ ((aligned (8)));
//typedef u16 u16a __attribute__ ((aligned (8)));
//typedef u32 u32a __attribute__ ((aligned (8)));
//typedef u64 u64a __attribute__ ((aligned (8)));

typedef u8  u8a;
typedef u16 u16a;
typedef u32 u32a;
typedef u64 u64a;

#ifndef NEW_SIMD_CODE
#undef  VECT_SIZE
#define VECT_SIZE 1
#endif

#define CONCAT(a, b)       a##b
#define VTYPE(type, width) CONCAT(type, width)

// emulated is always VECT_SIZE = 1
#if VECT_SIZE == 1
typedef u8   u8x;
typedef u16  u16x;
typedef u32  u32x;
typedef u64  u64x;

#define make_u8x  (u8)
#define make_u16x (u16)
#define make_u32x (u32)
#define make_u64x (u64)

#else

#if defined IS_CUDA || defined IS_HIP

#if VECT_SIZE == 2

struct __device_builtin__ __builtin_align__(2) u8x
{
  u8 s0;
  u8 s1;

  inline __device__  u8x (const u8 a, const u8 b) : s0(a), s1(b) { }
  inline __device__  u8x (const u8 a)             : s0(a), s1(a) { }

  inline __device__  u8x (void) : s0(0), s1(0) { }
  inline __device__ ~u8x (void) { }
};

struct __device_builtin__ __builtin_align__(4) u16x
{
  u16 s0;
  u16 s1;

  inline __device__  u16x (const u16 a, const u16 b) : s0(a), s1(b) { }
  inline __device__  u16x (const u16 a)              : s0(a), s1(a) { }

  inline __device__  u16x (void) : s0(0), s1(0) { }
  inline __device__ ~u16x (void) { }
};

struct __device_builtin__ __builtin_align__(8) u32x
{
  u32 s0;
  u32 s1;

  inline __device__  u32x (const u32 a, const u32 b) : s0(a), s1(b) { }
  inline __device__  u32x (const u32 a)              : s0(a), s1(a) { }

  inline __device__  u32x (void) : s0(0), s1(0) { }
  inline __device__ ~u32x (void) { }
};

struct __device_builtin__ __builtin_align__(16) u64x
{
  u64 s0;
  u64 s1;

  inline __device__  u64x (const u64 a, const u64 b) : s0(a), s1(b) { }
  inline __device__  u64x (const u64 a)              : s0(a), s1(a) { }

  inline __device__  u64x (void) : s0(0), s1(0) { }
  inline __device__ ~u64x (void) { }
};

inline __device__ bool operator != (const u32x a, const u32  b) { return ((a.s0 != b)    && (a.s1 != b));    }
inline __device__ bool operator != (const u32x a, const u32x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1)); }

inline __device__ void operator ^= (u32x &a, const u32  b) { a.s0 ^= b;    a.s1 ^= b;     }
inline __device__ void operator ^= (u32x &a, const u32x b) { a.s0 ^= b.s0; a.s1 ^= b.s1;  }

inline __device__ void operator |= (u32x &a, const u32  b) { a.s0 |= b;    a.s1 |= b;     }
inline __device__ void operator |= (u32x &a, const u32x b) { a.s0 |= b.s0; a.s1 |= b.s1;  }

inline __device__ void operator &= (u32x &a, const u32  b) { a.s0 &= b;    a.s1 &= b;     }
inline __device__ void operator &= (u32x &a, const u32x b) { a.s0 &= b.s0; a.s1 &= b.s1;  }

inline __device__ void operator += (u32x &a, const u32  b) { a.s0 += b;    a.s1 += b;     }
inline __device__ void operator += (u32x &a, const u32x b) { a.s0 += b.s0; a.s1 += b.s1;  }

inline __device__ void operator -= (u32x &a, const u32  b) { a.s0 -= b;    a.s1 -= b;     }
inline __device__ void operator -= (u32x &a, const u32x b) { a.s0 -= b.s0; a.s1 -= b.s1;  }

inline __device__ void operator *= (u32x &a, const u32  b) { a.s0 *= b;    a.s1 *= b;     }
inline __device__ void operator *= (u32x &a, const u32x b) { a.s0 *= b.s0; a.s1 *= b.s1;  }

inline __device__ void operator >>= (u32x &a, const u32  b) { a.s0 >>= b;    a.s1 >>= b;     }
inline __device__ void operator >>= (u32x &a, const u32x b) { a.s0 >>= b.s0; a.s1 >>= b.s1;  }

inline __device__ void operator <<= (u32x &a, const u32  b) { a.s0 <<= b;    a.s1 <<= b;     }
inline __device__ void operator <<= (u32x &a, const u32x b) { a.s0 <<= b.s0; a.s1 <<= b.s1;  }

inline __device__ u32x operator << (const u32x a, const u32  b) { return u32x ((a.s0 << b),    (a.s1 << b)   );  }
inline __device__ u32x operator << (const u32x a, const u32x b) { return u32x ((a.s0 << b.s0), (a.s1 << b.s1));  }

inline __device__ u32x operator >> (const u32x a, const u32  b) { return u32x ((a.s0 >> b),    (a.s1 >> b)   );  }
inline __device__ u32x operator >> (const u32x a, const u32x b) { return u32x ((a.s0 >> b.s0), (a.s1 >> b.s1));  }

inline __device__ u32x operator ^  (const u32x a, const u32  b) { return u32x ((a.s0 ^  b),    (a.s1 ^  b)   );  }
inline __device__ u32x operator ^  (const u32x a, const u32x b) { return u32x ((a.s0 ^  b.s0), (a.s1 ^  b.s1));  }

inline __device__ u32x operator |  (const u32x a, const u32  b) { return u32x ((a.s0 |  b),    (a.s1 |  b)   );  }
inline __device__ u32x operator |  (const u32x a, const u32x b) { return u32x ((a.s0 |  b.s0), (a.s1 |  b.s1));  }

inline __device__ u32x operator &  (const u32x a, const u32  b) { return u32x ((a.s0 &  b),    (a.s1 &  b)   );  }
inline __device__ u32x operator &  (const u32x a, const u32x b) { return u32x ((a.s0 &  b.s0), (a.s1 &  b.s1));  }

inline __device__ u32x operator +  (const u32x a, const u32  b) { return u32x ((a.s0 +  b),    (a.s1 +  b)   );  }
inline __device__ u32x operator +  (const u32x a, const u32x b) { return u32x ((a.s0 +  b.s0), (a.s1 +  b.s1));  }

inline __device__ u32x operator -  (const u32x a, const u32  b) { return u32x ((a.s0 -  b),    (a.s1 -  b)   );  }
inline __device__ u32x operator -  (const u32x a, const u32x b) { return u32x ((a.s0 -  b.s0), (a.s1 -  b.s1));  }

inline __device__ u32x operator *  (const u32x a, const u32  b) { return u32x ((a.s0 *  b),    (a.s1 *  b)   );  }
inline __device__ u32x operator *  (const u32x a, const u32x b) { return u32x ((a.s0 *  b.s0), (a.s1 *  b.s1));  }

inline __device__ u32x operator %  (const u32x a, const u32  b) { return u32x ((a.s0 %  b),    (a.s1 %  b)   );  }
inline __device__ u32x operator %  (const u32x a, const u32x b) { return u32x ((a.s0 %  b.s0), (a.s1 %  b.s1));  }

inline __device__ u32x operator ~  (const u32x a) { return u32x (~a.s0, ~a.s1); }

inline __device__ bool operator != (const u64x a, const u64  b) { return ((a.s0 != b)    && (a.s1 != b));    }
inline __device__ bool operator != (const u64x a, const u64x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1)); }

inline __device__ void operator ^= (u64x &a, const u64  b) { a.s0 ^= b;    a.s1 ^= b;     }
inline __device__ void operator ^= (u64x &a, const u64x b) { a.s0 ^= b.s0; a.s1 ^= b.s1;  }

inline __device__ void operator |= (u64x &a, const u64  b) { a.s0 |= b;    a.s1 |= b;     }
inline __device__ void operator |= (u64x &a, const u64x b) { a.s0 |= b.s0; a.s1 |= b.s1;  }

inline __device__ void operator &= (u64x &a, const u64  b) { a.s0 &= b;    a.s1 &= b;     }
inline __device__ void operator &= (u64x &a, const u64x b) { a.s0 &= b.s0; a.s1 &= b.s1;  }

inline __device__ void operator += (u64x &a, const u64  b) { a.s0 += b;    a.s1 += b;     }
inline __device__ void operator += (u64x &a, const u64x b) { a.s0 += b.s0; a.s1 += b.s1;  }

inline __device__ void operator -= (u64x &a, const u64  b) { a.s0 -= b;    a.s1 -= b;     }
inline __device__ void operator -= (u64x &a, const u64x b) { a.s0 -= b.s0; a.s1 -= b.s1;  }

inline __device__ void operator *= (u64x &a, const u64  b) { a.s0 *= b;    a.s1 *= b;     }
inline __device__ void operator *= (u64x &a, const u64x b) { a.s0 *= b.s0; a.s1 *= b.s1;  }

inline __device__ void operator >>= (u64x &a, const u64  b) { a.s0 >>= b;    a.s1 >>= b;     }
inline __device__ void operator >>= (u64x &a, const u64x b) { a.s0 >>= b.s0; a.s1 >>= b.s1;  }

inline __device__ void operator <<= (u64x &a, const u64  b) { a.s0 <<= b;    a.s1 <<= b;     }
inline __device__ void operator <<= (u64x &a, const u64x b) { a.s0 <<= b.s0; a.s1 <<= b.s1;  }

inline __device__ u64x operator << (const u64x a, const u64  b) { return u64x ((a.s0 << b),    (a.s1 << b)   );  }
inline __device__ u64x operator << (const u64x a, const u64x b) { return u64x ((a.s0 << b.s0), (a.s1 << b.s1));  }

inline __device__ u64x operator >> (const u64x a, const u64  b) { return u64x ((a.s0 >> b),    (a.s1 >> b)   );  }
inline __device__ u64x operator >> (const u64x a, const u64x b) { return u64x ((a.s0 >> b.s0), (a.s1 >> b.s1));  }

inline __device__ u64x operator ^  (const u64x a, const u64  b) { return u64x ((a.s0 ^  b),    (a.s1 ^  b)   );  }
inline __device__ u64x operator ^  (const u64x a, const u64x b) { return u64x ((a.s0 ^  b.s0), (a.s1 ^  b.s1));  }

inline __device__ u64x operator |  (const u64x a, const u64  b) { return u64x ((a.s0 |  b),    (a.s1 |  b)   );  }
inline __device__ u64x operator |  (const u64x a, const u64x b) { return u64x ((a.s0 |  b.s0), (a.s1 |  b.s1));  }

inline __device__ u64x operator &  (const u64x a, const u64  b) { return u64x ((a.s0 &  b),    (a.s1 &  b)   );  }
inline __device__ u64x operator &  (const u64x a, const u64x b) { return u64x ((a.s0 &  b.s0), (a.s1 &  b.s1));  }

inline __device__ u64x operator +  (const u64x a, const u64  b) { return u64x ((a.s0 +  b),    (a.s1 +  b)   );  }
inline __device__ u64x operator +  (const u64x a, const u64x b) { return u64x ((a.s0 +  b.s0), (a.s1 +  b.s1));  }

inline __device__ u64x operator -  (const u64x a, const u64  b) { return u64x ((a.s0 -  b),    (a.s1 -  b)   );  }
inline __device__ u64x operator -  (const u64x a, const u64x b) { return u64x ((a.s0 -  b.s0), (a.s1 -  b.s1));  }

inline __device__ u64x operator *  (const u64x a, const u64  b) { return u64x ((a.s0 *  b),    (a.s1 *  b)   );  }
inline __device__ u64x operator *  (const u64x a, const u64x b) { return u64x ((a.s0 *  b.s0), (a.s1 *  b.s1));  }

inline __device__ u64x operator %  (const u64x a, const u64  b) { return u64x ((a.s0 %  b),    (a.s1 %  b)   );  }
inline __device__ u64x operator %  (const u64x a, const u64x b) { return u64x ((a.s0 %  b.s0), (a.s1 %  b.s1));  }

inline __device__ u64x operator ~  (const u64x a) { return u64x (~a.s0, ~a.s1); }

#endif

#if VECT_SIZE == 4

struct __device_builtin__ __builtin_align__(4) u8x
{
  u8 s0;
  u8 s1;
  u8 s2;
  u8 s3;

  inline __device__  u8x (const u8 a, const u8 b, const u8 c, const u8 d) : s0(a), s1(b), s2(c), s3(d) { }
  inline __device__  u8x (const u8 a)                                     : s0(a), s1(a), s2(a), s3(a) { }

  inline __device__  u8x (void) : s0(0), s1(0), s2(0), s3(0) { }
  inline __device__ ~u8x (void) { }
};

struct __device_builtin__ __builtin_align__(8) u16x
{
  u16 s0;
  u16 s1;
  u16 s2;
  u16 s3;

  inline __device__  u16x (const u16 a, const u16 b, const u16 c, const u16 d) : s0(a), s1(b), s2(c), s3(d) { }
  inline __device__  u16x (const u16 a)                                        : s0(a), s1(a), s2(a), s3(a) { }

  inline __device__  u16x (void) : s0(0), s1(0), s2(0), s3(0) { }
  inline __device__ ~u16x (void) { }
};

struct __device_builtin__ __builtin_align__(16) u32x
{
  u32 s0;
  u32 s1;
  u32 s2;
  u32 s3;

  inline __device__  u32x (const u32 a, const u32 b, const u32 c, const u32 d) : s0(a), s1(b), s2(c), s3(d) { }
  inline __device__  u32x (const u32 a)                                        : s0(a), s1(a), s2(a), s3(a) { }

  inline __device__  u32x (void) : s0(0), s1(0), s2(0), s3(0) { }
  inline __device__ ~u32x (void) { }
};

struct __device_builtin__ __builtin_align__(32) u64x
{
  u64 s0;
  u64 s1;
  u64 s2;
  u64 s3;

  inline __device__  u64x (const u64 a, const u64 b, const u64 c, const u64 d) : s0(a), s1(b), s2(c), s3(d) { }
  inline __device__  u64x (const u64 a)                                        : s0(a), s1(a), s2(a), s3(a) { }

  inline __device__  u64x (void) : s0(0), s1(0), s2(0), s3(0) { }
  inline __device__ ~u64x (void) { }
};

inline __device__ bool operator != (const u32x a, const u32  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)   ); }
inline __device__ bool operator != (const u32x a, const u32x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3)); }

inline __device__ void operator ^= (u32x &a, const u32  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;     }
inline __device__ void operator ^= (u32x &a, const u32x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3;  }

inline __device__ void operator |= (u32x &a, const u32  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;     }
inline __device__ void operator |= (u32x &a, const u32x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3;  }

inline __device__ void operator &= (u32x &a, const u32  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;     }
inline __device__ void operator &= (u32x &a, const u32x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3;  }

inline __device__ void operator += (u32x &a, const u32  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;     }
inline __device__ void operator += (u32x &a, const u32x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3;  }

inline __device__ void operator -= (u32x &a, const u32  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;     }
inline __device__ void operator -= (u32x &a, const u32x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3;  }

inline __device__ void operator *= (u32x &a, const u32  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;     }
inline __device__ void operator *= (u32x &a, const u32x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3;  }

inline __device__ void operator >>= (u32x &a, const u32  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;     }
inline __device__ void operator >>= (u32x &a, const u32x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3;  }

inline __device__ void operator <<= (u32x &a, const u32  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;     }
inline __device__ void operator <<= (u32x &a, const u32x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3;  }

inline __device__ u32x operator << (const u32x a, const u32  b) { return u32x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   );  }
inline __device__ u32x operator << (const u32x a, const u32x b) { return u32x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3));  }

inline __device__ u32x operator >> (const u32x a, const u32  b) { return u32x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   );  }
inline __device__ u32x operator >> (const u32x a, const u32x b) { return u32x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3));  }

inline __device__ u32x operator ^  (const u32x a, const u32  b) { return u32x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   );  }
inline __device__ u32x operator ^  (const u32x a, const u32x b) { return u32x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3));  }

inline __device__ u32x operator |  (const u32x a, const u32  b) { return u32x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   );  }
inline __device__ u32x operator |  (const u32x a, const u32x b) { return u32x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3));  }

inline __device__ u32x operator &  (const u32x a, const u32  b) { return u32x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   );  }
inline __device__ u32x operator &  (const u32x a, const u32x b) { return u32x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3));  }

inline __device__ u32x operator +  (const u32x a, const u32  b) { return u32x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   );  }
inline __device__ u32x operator +  (const u32x a, const u32x b) { return u32x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3));  }

inline __device__ u32x operator -  (const u32x a, const u32  b) { return u32x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   );  }
inline __device__ u32x operator -  (const u32x a, const u32x b) { return u32x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3));  }

inline __device__ u32x operator *  (const u32x a, const u32  b) { return u32x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   );  }
inline __device__ u32x operator *  (const u32x a, const u32x b) { return u32x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3));  }

inline __device__ u32x operator %  (const u32x a, const u32  b) { return u32x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   );  }
inline __device__ u32x operator %  (const u32x a, const u32x b) { return u32x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3));  }

inline __device__ u32x operator ~  (const u32x a) { return u32x (~a.s0, ~a.s1, ~a.s2, ~a.s3); }

inline __device__ bool operator != (const u64x a, const u64  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)   ); }
inline __device__ bool operator != (const u64x a, const u64x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3)); }

inline __device__ void operator ^= (u64x &a, const u64  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;     }
inline __device__ void operator ^= (u64x &a, const u64x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3;  }

inline __device__ void operator |= (u64x &a, const u64  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;     }
inline __device__ void operator |= (u64x &a, const u64x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3;  }

inline __device__ void operator &= (u64x &a, const u64  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;     }
inline __device__ void operator &= (u64x &a, const u64x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3;  }

inline __device__ void operator += (u64x &a, const u64  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;     }
inline __device__ void operator += (u64x &a, const u64x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3;  }

inline __device__ void operator -= (u64x &a, const u64  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;     }
inline __device__ void operator -= (u64x &a, const u64x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3;  }

inline __device__ void operator *= (u64x &a, const u64  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;     }
inline __device__ void operator *= (u64x &a, const u64x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3;  }

inline __device__ void operator >>= (u64x &a, const u64  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;     }
inline __device__ void operator >>= (u64x &a, const u64x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3;  }

inline __device__ void operator <<= (u64x &a, const u64  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;     }
inline __device__ void operator <<= (u64x &a, const u64x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3;  }

inline __device__ u64x operator << (const u64x a, const u64  b) { return u64x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   );  }
inline __device__ u64x operator << (const u64x a, const u64x b) { return u64x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3));  }

inline __device__ u64x operator >> (const u64x a, const u64  b) { return u64x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   );  }
inline __device__ u64x operator >> (const u64x a, const u64x b) { return u64x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3));  }

inline __device__ u64x operator ^  (const u64x a, const u64  b) { return u64x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   );  }
inline __device__ u64x operator ^  (const u64x a, const u64x b) { return u64x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3));  }

inline __device__ u64x operator |  (const u64x a, const u64  b) { return u64x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   );  }
inline __device__ u64x operator |  (const u64x a, const u64x b) { return u64x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3));  }

inline __device__ u64x operator &  (const u64x a, const u64  b) { return u64x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   );  }
inline __device__ u64x operator &  (const u64x a, const u64x b) { return u64x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3));  }

inline __device__ u64x operator +  (const u64x a, const u64  b) { return u64x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   );  }
inline __device__ u64x operator +  (const u64x a, const u64x b) { return u64x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3));  }

inline __device__ u64x operator -  (const u64x a, const u64  b) { return u64x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   );  }
inline __device__ u64x operator -  (const u64x a, const u64x b) { return u64x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3));  }

inline __device__ u64x operator *  (const u64x a, const u64  b) { return u64x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   );  }
inline __device__ u64x operator *  (const u64x a, const u64x b) { return u64x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3));  }

inline __device__ u64x operator %  (const u64x a, const u32  b) { return u64x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   );  }
inline __device__ u64x operator %  (const u64x a, const u64x b) { return u64x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3));  }

inline __device__ u64x operator ~  (const u64x a) { return u64x (~a.s0, ~a.s1, ~a.s2, ~a.s3); }

#endif

#if VECT_SIZE == 8

struct __device_builtin__ __builtin_align__(8) u8x
{
  u8 s0;
  u8 s1;
  u8 s2;
  u8 s3;
  u8 s4;
  u8 s5;
  u8 s6;
  u8 s7;

  inline __device__  u8x (const u8 a, const u8 b, const u8 c, const u8 d, const u8 e, const u8 f, const u8 g, const u8 h) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h) { }
  inline __device__  u8x (const u8 a)                                                                                     : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a) { }

  inline __device__  u8x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0) { }
  inline __device__ ~u8x (void) { }
};

struct __device_builtin__ __builtin_align__(16) u16x
{
  u16 s0;
  u16 s1;
  u16 s2;
  u16 s3;
  u16 s4;
  u16 s5;
  u16 s6;
  u16 s7;

  inline __device__  u16x (const u16 a, const u16 b, const u16 c, const u16 d, const u16 e, const u16 f, const u16 g, const u16 h) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h) { }
  inline __device__  u16x (const u16 a)                                                                                            : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a) { }

  inline __device__  u16x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0) { }
  inline __device__ ~u16x (void) { }
};

struct __device_builtin__ __builtin_align__(32) u32x
{
  u32 s0;
  u32 s1;
  u32 s2;
  u32 s3;
  u32 s4;
  u32 s5;
  u32 s6;
  u32 s7;

  inline __device__  u32x (const u32 a, const u32 b, const u32 c, const u32 d, const u32 e, const u32 f, const u32 g, const u32 h) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h) { }
  inline __device__  u32x (const u32 a)                                                                                            : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a) { }

  inline __device__  u32x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0) { }
  inline __device__ ~u32x (void) { }
};

struct __device_builtin__ __builtin_align__(64) u64x
{
  u64 s0;
  u64 s1;
  u64 s2;
  u64 s3;
  u64 s4;
  u64 s5;
  u64 s6;
  u64 s7;

  inline __device__  u64x (const u64 a, const u64 b, const u64 c, const u64 d, const u64 e, const u64 f, const u64 g, const u64 h) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h) { }
  inline __device__  u64x (const u64 a)                                                                                            : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a) { }

  inline __device__  u64x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0) { }
  inline __device__ ~u64x (void) { }
};

inline __device__ bool operator != (const u32x a, const u32  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)    && (a.s4 != b)    && (a.s5 != b)    && (a.s6 != b)    && (a.s7 != b)   ); }
inline __device__ bool operator != (const u32x a, const u32x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3) && (a.s4 != b.s4) && (a.s5 != b.s5) && (a.s6 != b.s6) && (a.s7 != b.s7)); }

inline __device__ void operator ^= (u32x &a, const u32  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;    a.s4 ^= b;    a.s5 ^= b;    a.s6 ^= b;    a.s7 ^= b;     }
inline __device__ void operator ^= (u32x &a, const u32x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3; a.s4 ^= b.s4; a.s5 ^= b.s5; a.s6 ^= b.s6; a.s7 ^= b.s7;  }

inline __device__ void operator |= (u32x &a, const u32  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;    a.s4 |= b;    a.s5 |= b;    a.s6 |= b;    a.s7 |= b;     }
inline __device__ void operator |= (u32x &a, const u32x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3; a.s4 |= b.s4; a.s5 |= b.s5; a.s6 |= b.s6; a.s7 |= b.s7;  }

inline __device__ void operator &= (u32x &a, const u32  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;    a.s4 &= b;    a.s5 &= b;    a.s6 &= b;    a.s7 &= b;     }
inline __device__ void operator &= (u32x &a, const u32x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3; a.s4 &= b.s4; a.s5 &= b.s5; a.s6 &= b.s6; a.s7 &= b.s7;  }

inline __device__ void operator += (u32x &a, const u32  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;    a.s4 += b;    a.s5 += b;    a.s6 += b;    a.s7 += b;     }
inline __device__ void operator += (u32x &a, const u32x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3; a.s4 += b.s4; a.s5 += b.s5; a.s6 += b.s6; a.s7 += b.s7;  }

inline __device__ void operator -= (u32x &a, const u32  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;    a.s4 -= b;    a.s5 -= b;    a.s6 -= b;    a.s7 -= b;     }
inline __device__ void operator -= (u32x &a, const u32x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3; a.s4 -= b.s4; a.s5 -= b.s5; a.s6 -= b.s6; a.s7 -= b.s7;  }

inline __device__ void operator *= (u32x &a, const u32  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;    a.s4 *= b;    a.s5 *= b;    a.s6 *= b;    a.s7 *= b;     }
inline __device__ void operator *= (u32x &a, const u32x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3; a.s4 *= b.s4; a.s5 *= b.s5; a.s6 *= b.s6; a.s7 *= b.s7;  }

inline __device__ void operator >>= (u32x &a, const u32  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;    a.s4 >>= b;    a.s5 >>= b;    a.s6 >>= b;    a.s7 >>= b;     }
inline __device__ void operator >>= (u32x &a, const u32x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3; a.s4 >>= b.s4; a.s5 >>= b.s5; a.s6 >>= b.s6; a.s7 >>= b.s7;  }

inline __device__ void operator <<= (u32x &a, const u32  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;    a.s4 <<= b;    a.s5 <<= b;    a.s6 <<= b;    a.s7 <<= b;     }
inline __device__ void operator <<= (u32x &a, const u32x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3; a.s4 <<= b.s4; a.s5 <<= b.s5; a.s6 <<= b.s6; a.s7 <<= b.s7;  }

inline __device__ u32x operator << (const u32x a, const u32  b) { return u32x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   , (a.s4 << b),    (a.s5 << b)   , (a.s6 << b),    (a.s7 << b)   );  }
inline __device__ u32x operator << (const u32x a, const u32x b) { return u32x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3), (a.s4 << b.s4), (a.s5 << b.s5), (a.s6 << b.s6), (a.s7 << b.s7));  }

inline __device__ u32x operator >> (const u32x a, const u32  b) { return u32x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   , (a.s4 >> b),    (a.s5 >> b)   , (a.s6 >> b),    (a.s7 >> b)   );  }
inline __device__ u32x operator >> (const u32x a, const u32x b) { return u32x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3), (a.s4 >> b.s4), (a.s5 >> b.s5), (a.s6 >> b.s6), (a.s7 >> b.s7));  }

inline __device__ u32x operator ^  (const u32x a, const u32  b) { return u32x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   , (a.s4 ^  b),    (a.s5 ^  b)   , (a.s6 ^  b),    (a.s7 ^  b)   );  }
inline __device__ u32x operator ^  (const u32x a, const u32x b) { return u32x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3), (a.s4 ^  b.s4), (a.s5 ^  b.s5), (a.s6 ^  b.s6), (a.s7 ^  b.s7));  }

inline __device__ u32x operator |  (const u32x a, const u32  b) { return u32x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   , (a.s4 |  b),    (a.s5 |  b)   , (a.s6 |  b),    (a.s7 |  b)   );  }
inline __device__ u32x operator |  (const u32x a, const u32x b) { return u32x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3), (a.s4 |  b.s4), (a.s5 |  b.s5), (a.s6 |  b.s6), (a.s7 |  b.s7));  }

inline __device__ u32x operator &  (const u32x a, const u32  b) { return u32x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   , (a.s4 &  b),    (a.s5 &  b)   , (a.s6 &  b),    (a.s7 &  b)   );  }
inline __device__ u32x operator &  (const u32x a, const u32x b) { return u32x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3), (a.s4 &  b.s4), (a.s5 &  b.s5), (a.s6 &  b.s6), (a.s7 &  b.s7));  }

inline __device__ u32x operator +  (const u32x a, const u32  b) { return u32x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   , (a.s4 +  b),    (a.s5 +  b)   , (a.s6 +  b),    (a.s7 +  b)   );  }
inline __device__ u32x operator +  (const u32x a, const u32x b) { return u32x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3), (a.s4 +  b.s4), (a.s5 +  b.s5), (a.s6 +  b.s6), (a.s7 +  b.s7));  }

inline __device__ u32x operator -  (const u32x a, const u32  b) { return u32x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   , (a.s4 -  b),    (a.s5 -  b)   , (a.s6 -  b),    (a.s7 -  b)   );  }
inline __device__ u32x operator -  (const u32x a, const u32x b) { return u32x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3), (a.s4 -  b.s4), (a.s5 -  b.s5), (a.s6 -  b.s6), (a.s7 -  b.s7));  }

inline __device__ u32x operator *  (const u32x a, const u32  b) { return u32x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   , (a.s4 *  b),    (a.s5 *  b)   , (a.s6 *  b),    (a.s7 *  b)   );  }
inline __device__ u32x operator *  (const u32x a, const u32x b) { return u32x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3), (a.s4 *  b.s4), (a.s5 *  b.s5), (a.s6 *  b.s6), (a.s7 *  b.s7));  }

inline __device__ u32x operator %  (const u32x a, const u32  b) { return u32x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   , (a.s4 %  b),    (a.s5 %  b)   , (a.s6 %  b),    (a.s7 %  b)   );  }
inline __device__ u32x operator %  (const u32x a, const u32x b) { return u32x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3), (a.s4 %  b.s4), (a.s5 %  b.s5), (a.s6 %  b.s6), (a.s7 %  b.s7));  }

inline __device__ u32x operator ~  (const u32x a) { return u32x (~a.s0, ~a.s1, ~a.s2, ~a.s3, ~a.s4, ~a.s5, ~a.s6, ~a.s7); }

inline __device__ bool operator != (const u64x a, const u64  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)    && (a.s4 != b)    && (a.s5 != b)    && (a.s6 != b)    && (a.s7 != b)   ); }
inline __device__ bool operator != (const u64x a, const u64x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3) && (a.s4 != b.s4) && (a.s5 != b.s5) && (a.s6 != b.s6) && (a.s7 != b.s7)); }

inline __device__ void operator ^= (u64x &a, const u64  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;    a.s4 ^= b;    a.s5 ^= b;    a.s6 ^= b;    a.s7 ^= b;     }
inline __device__ void operator ^= (u64x &a, const u64x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3; a.s4 ^= b.s4; a.s5 ^= b.s5; a.s6 ^= b.s6; a.s7 ^= b.s7;  }

inline __device__ void operator |= (u64x &a, const u64  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;    a.s4 |= b;    a.s5 |= b;    a.s6 |= b;    a.s7 |= b;     }
inline __device__ void operator |= (u64x &a, const u64x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3; a.s4 |= b.s4; a.s5 |= b.s5; a.s6 |= b.s6; a.s7 |= b.s7;  }

inline __device__ void operator &= (u64x &a, const u64  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;    a.s4 &= b;    a.s5 &= b;    a.s6 &= b;    a.s7 &= b;     }
inline __device__ void operator &= (u64x &a, const u64x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3; a.s4 &= b.s4; a.s5 &= b.s5; a.s6 &= b.s6; a.s7 &= b.s7;  }

inline __device__ void operator += (u64x &a, const u64  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;    a.s4 += b;    a.s5 += b;    a.s6 += b;    a.s7 += b;     }
inline __device__ void operator += (u64x &a, const u64x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3; a.s4 += b.s4; a.s5 += b.s5; a.s6 += b.s6; a.s7 += b.s7;  }

inline __device__ void operator -= (u64x &a, const u64  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;    a.s4 -= b;    a.s5 -= b;    a.s6 -= b;    a.s7 -= b;     }
inline __device__ void operator -= (u64x &a, const u64x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3; a.s4 -= b.s4; a.s5 -= b.s5; a.s6 -= b.s6; a.s7 -= b.s7;  }

inline __device__ void operator *= (u64x &a, const u64  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;    a.s4 *= b;    a.s5 *= b;    a.s6 *= b;    a.s7 *= b;     }
inline __device__ void operator *= (u64x &a, const u64x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3; a.s4 *= b.s4; a.s5 *= b.s5; a.s6 *= b.s6; a.s7 *= b.s7;  }

inline __device__ void operator >>= (u64x &a, const u64  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;    a.s4 >>= b;    a.s5 >>= b;    a.s6 >>= b;    a.s7 >>= b;     }
inline __device__ void operator >>= (u64x &a, const u64x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3; a.s4 >>= b.s4; a.s5 >>= b.s5; a.s6 >>= b.s6; a.s7 >>= b.s7;  }

inline __device__ void operator <<= (u64x &a, const u64  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;    a.s4 <<= b;    a.s5 <<= b;    a.s6 <<= b;    a.s7 <<= b;     }
inline __device__ void operator <<= (u64x &a, const u64x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3; a.s4 <<= b.s4; a.s5 <<= b.s5; a.s6 <<= b.s6; a.s7 <<= b.s7;  }

inline __device__ u64x operator << (const u64x a, const u64  b) { return u64x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   , (a.s4 << b),    (a.s5 << b)   , (a.s6 << b),    (a.s7 << b)   );  }
inline __device__ u64x operator << (const u64x a, const u64x b) { return u64x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3), (a.s4 << b.s4), (a.s5 << b.s5), (a.s6 << b.s6), (a.s7 << b.s7));  }

inline __device__ u64x operator >> (const u64x a, const u64  b) { return u64x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   , (a.s4 >> b),    (a.s5 >> b)   , (a.s6 >> b),    (a.s7 >> b)   );  }
inline __device__ u64x operator >> (const u64x a, const u64x b) { return u64x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3), (a.s4 >> b.s4), (a.s5 >> b.s5), (a.s6 >> b.s6), (a.s7 >> b.s7));  }

inline __device__ u64x operator ^  (const u64x a, const u64  b) { return u64x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   , (a.s4 ^  b),    (a.s5 ^  b)   , (a.s6 ^  b),    (a.s7 ^  b)   );  }
inline __device__ u64x operator ^  (const u64x a, const u64x b) { return u64x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3), (a.s4 ^  b.s4), (a.s5 ^  b.s5), (a.s6 ^  b.s6), (a.s7 ^  b.s7));  }

inline __device__ u64x operator |  (const u64x a, const u64  b) { return u64x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   , (a.s4 |  b),    (a.s5 |  b)   , (a.s6 |  b),    (a.s7 |  b)   );  }
inline __device__ u64x operator |  (const u64x a, const u64x b) { return u64x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3), (a.s4 |  b.s4), (a.s5 |  b.s5), (a.s6 |  b.s6), (a.s7 |  b.s7));  }

inline __device__ u64x operator &  (const u64x a, const u64  b) { return u64x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   , (a.s4 &  b),    (a.s5 &  b)   , (a.s6 &  b),    (a.s7 &  b)   );  }
inline __device__ u64x operator &  (const u64x a, const u64x b) { return u64x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3), (a.s4 &  b.s4), (a.s5 &  b.s5), (a.s6 &  b.s6), (a.s7 &  b.s7));  }

inline __device__ u64x operator +  (const u64x a, const u64  b) { return u64x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   , (a.s4 +  b),    (a.s5 +  b)   , (a.s6 +  b),    (a.s7 +  b)   );  }
inline __device__ u64x operator +  (const u64x a, const u64x b) { return u64x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3), (a.s4 +  b.s4), (a.s5 +  b.s5), (a.s6 +  b.s6), (a.s7 +  b.s7));  }

inline __device__ u64x operator -  (const u64x a, const u64  b) { return u64x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   , (a.s4 -  b),    (a.s5 -  b)   , (a.s6 -  b),    (a.s7 -  b)   );  }
inline __device__ u64x operator -  (const u64x a, const u64x b) { return u64x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3), (a.s4 -  b.s4), (a.s5 -  b.s5), (a.s6 -  b.s6), (a.s7 -  b.s7));  }

inline __device__ u64x operator *  (const u64x a, const u64  b) { return u64x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   , (a.s4 *  b),    (a.s5 *  b)   , (a.s6 *  b),    (a.s7 *  b)   );  }
inline __device__ u64x operator *  (const u64x a, const u64x b) { return u64x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3), (a.s4 *  b.s4), (a.s5 *  b.s5), (a.s6 *  b.s6), (a.s7 *  b.s7));  }

inline __device__ u64x operator %  (const u64x a, const u64  b) { return u64x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   , (a.s4 %  b),    (a.s5 %  b)   , (a.s6 %  b),    (a.s7 %  b)   );  }
inline __device__ u64x operator %  (const u64x a, const u64x b) { return u64x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3), (a.s4 %  b.s4), (a.s5 %  b.s5), (a.s6 %  b.s6), (a.s7 %  b.s7));  }

inline __device__ u64x operator ~  (const u64x a) { return u64x (~a.s0, ~a.s1, ~a.s2, ~a.s3, ~a.s4, ~a.s5, ~a.s6, ~a.s7); }

#endif

#if VECT_SIZE == 16

struct __device_builtin__ __builtin_align__(16) u8x
{
  u8 s0;
  u8 s1;
  u8 s2;
  u8 s3;
  u8 s4;
  u8 s5;
  u8 s6;
  u8 s7;
  u8 s8;
  u8 s9;
  u8 sa;
  u8 sb;
  u8 sc;
  u8 sd;
  u8 se;
  u8 sf;

  inline __device__  u8x (const u8 a, const u8 b, const u8 c, const u8 d, const u8 e, const u8 f, const u8 g, const u8 h, const u8 i, const u8 j, const u8 k, const u8 l, const u8 m, const u8 n, const u8 o, const u8 p) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h), s8(i), s9(j), sa(k), sb(l), sc(m), sd(n), se(o), sf(p) { }
  inline __device__  u8x (const u8 a)                                                                                                                                                                                     : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a), s8(a), s9(a), sa(a), sb(a), sc(a), sd(a), se(a), sf(a) { }

  inline __device__  u8x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0), s8(0), s9(0), sa(0), sb(0), sc(0), sd(0), se(0), sf(0) { }
  inline __device__ ~u8x (void) { }
};

struct __device_builtin__ __builtin_align__(32) u16x
{
  u16 s0;
  u16 s1;
  u16 s2;
  u16 s3;
  u16 s4;
  u16 s5;
  u16 s6;
  u16 s7;
  u16 s8;
  u16 s9;
  u16 sa;
  u16 sb;
  u16 sc;
  u16 sd;
  u16 se;
  u16 sf;

  inline __device__  u16x (const u16 a, const u16 b, const u16 c, const u16 d, const u16 e, const u16 f, const u16 g, const u16 h, const u16 i, const u16 j, const u16 k, const u16 l, const u16 m, const u16 n, const u16 o, const u16 p) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h), s8(i), s9(j), sa(k), sb(l), sc(m), sd(n), se(o), sf(p) { }
  inline __device__  u16x (const u16 a)                                                                                                                                                                                     : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a), s8(a), s9(a), sa(a), sb(a), sc(a), sd(a), se(a), sf(a) { }

  inline __device__  u16x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0), s8(0), s9(0), sa(0), sb(0), sc(0), sd(0), se(0), sf(0){ }
  inline __device__ ~u16x (void) { }
};

struct __device_builtin__ __builtin_align__(64) u32x
{
  u32 s0;
  u32 s1;
  u32 s2;
  u32 s3;
  u32 s4;
  u32 s5;
  u32 s6;
  u32 s7;
  u32 s8;
  u32 s9;
  u32 sa;
  u32 sb;
  u32 sc;
  u32 sd;
  u32 se;
  u32 sf;

  inline __device__  u32x (const u32 a, const u32 b, const u32 c, const u32 d, const u32 e, const u32 f, const u32 g, const u32 h, const u32 i, const u32 j, const u32 k, const u32 l, const u32 m, const u32 n, const u32 o, const u32 p) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h), s8(i), s9(j), sa(k), sb(l), sc(m), sd(n), se(o), sf(p) { }
  inline __device__  u32x (const u32 a)                                                                                                                                                                                     : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a), s8(a), s9(a), sa(a), sb(a), sc(a), sd(a), se(a), sf(a) { }

  inline __device__  u32x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0), s8(0), s9(0), sa(0), sb(0), sc(0), sd(0), se(0), sf(0){ }
  inline __device__ ~u32x (void) { }
};

struct __device_builtin__ __builtin_align__(128) u64x
{
  u64 s0;
  u64 s1;
  u64 s2;
  u64 s3;
  u64 s4;
  u64 s5;
  u64 s6;
  u64 s7;
  u64 s8;
  u64 s9;
  u64 sa;
  u64 sb;
  u64 sc;
  u64 sd;
  u64 se;
  u64 sf;

  inline __device__  u64x (const u64 a, const u64 b, const u64 c, const u64 d, const u64 e, const u64 f, const u64 g, const u64 h, const u64 i, const u64 j, const u64 k, const u64 l, const u64 m, const u64 n, const u64 o, const u64 p) : s0(a), s1(b), s2(c), s3(d), s4(e), s5(f), s6(g), s7(h), s8(i), s9(j), sa(k), sb(l), sc(m), sd(n), se(o), sf(p) { }
  inline __device__  u64x (const u64 a)                                                                                                                                                                                     : s0(a), s1(a), s2(a), s3(a), s4(a), s5(a), s6(a), s7(a), s8(a), s9(a), sa(a), sb(a), sc(a), sd(a), se(a), sf(a) { }

  inline __device__  u64x (void) : s0(0), s1(0), s2(0), s3(0), s4(0), s5(0), s6(0), s7(0), s8(0), s9(0), sa(0), sb(0), sc(0), sd(0), se(0), sf(0) { }
  inline __device__ ~u64x (void) { }
};

inline __device__ bool operator != (const u32x a, const u32  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)    && (a.s4 != b)    && (a.s5 != b)    && (a.s6 != b)    && (a.s7 != b)    && (a.s8 != b)    && (a.s9 != b)    && (a.sa != b)    && (a.sb != b)    && (a.sc != b)    && (a.sd != b)    && (a.se != b)    && (a.sf != b)   ); }
inline __device__ bool operator != (const u32x a, const u32x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3) && (a.s4 != b.s4) && (a.s5 != b.s5) && (a.s6 != b.s6) && (a.s7 != b.s7) && (a.s8 != b.s8) && (a.s9 != b.s9) && (a.sa != b.sa) && (a.sb != b.sb) && (a.sc != b.sc) && (a.sd != b.sd) && (a.se != b.se) && (a.sf != b.sf)); }

inline __device__ void operator ^= (u32x &a, const u32  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;    a.s4 ^= b;    a.s5 ^= b;    a.s6 ^= b;    a.s7 ^= b;    a.s8 ^= b;    a.s9 ^= b;    a.sa ^= b;    a.sb ^= b;    a.sc ^= b;    a.sd ^= b;    a.se ^= b;    a.sf ^= b;    }
inline __device__ void operator ^= (u32x &a, const u32x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3; a.s4 ^= b.s4; a.s5 ^= b.s5; a.s6 ^= b.s6; a.s7 ^= b.s7; a.s8 ^= b.s8; a.s9 ^= b.s9; a.sa ^= b.sa; a.sb ^= b.sb; a.sc ^= b.sc; a.sd ^= b.sd; a.se ^= b.se; a.sf ^= b.sf; }

inline __device__ void operator |= (u32x &a, const u32  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;    a.s4 |= b;    a.s5 |= b;    a.s6 |= b;    a.s7 |= b;    a.s8 |= b;    a.s9 |= b;    a.sa |= b;    a.sb |= b;    a.sc |= b;    a.sd |= b;    a.se |= b;    a.sf |= b;    }
inline __device__ void operator |= (u32x &a, const u32x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3; a.s4 |= b.s4; a.s5 |= b.s5; a.s6 |= b.s6; a.s7 |= b.s7; a.s8 |= b.s8; a.s9 |= b.s9; a.sa |= b.sa; a.sb |= b.sb; a.sc |= b.sc; a.sd |= b.sd; a.se |= b.se; a.sf |= b.sf; }

inline __device__ void operator &= (u32x &a, const u32  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;    a.s4 &= b;    a.s5 &= b;    a.s6 &= b;    a.s7 &= b;    a.s8 &= b;    a.s9 &= b;    a.sa &= b;    a.sb &= b;    a.sc &= b;    a.sd &= b;    a.se &= b;    a.sf &= b;    }
inline __device__ void operator &= (u32x &a, const u32x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3; a.s4 &= b.s4; a.s5 &= b.s5; a.s6 &= b.s6; a.s7 &= b.s7; a.s8 &= b.s8; a.s9 &= b.s9; a.sa &= b.sa; a.sb &= b.sb; a.sc &= b.sc; a.sd &= b.sd; a.se &= b.se; a.sf &= b.sf; }

inline __device__ void operator += (u32x &a, const u32  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;    a.s4 += b;    a.s5 += b;    a.s6 += b;    a.s7 += b;    a.s8 += b;    a.s9 += b;    a.sa += b;    a.sb += b;    a.sc += b;    a.sd += b;    a.se += b;    a.sf += b;    }
inline __device__ void operator += (u32x &a, const u32x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3; a.s4 += b.s4; a.s5 += b.s5; a.s6 += b.s6; a.s7 += b.s7; a.s8 += b.s8; a.s9 += b.s9; a.sa += b.sa; a.sb += b.sb; a.sc += b.sc; a.sd += b.sd; a.se += b.se; a.sf += b.sf; }

inline __device__ void operator -= (u32x &a, const u32  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;    a.s4 -= b;    a.s5 -= b;    a.s6 -= b;    a.s7 -= b;    a.s8 -= b;    a.s9 -= b;    a.sa -= b;    a.sb -= b;    a.sc -= b;    a.sd -= b;    a.se -= b;    a.sf -= b;    }
inline __device__ void operator -= (u32x &a, const u32x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3; a.s4 -= b.s4; a.s5 -= b.s5; a.s6 -= b.s6; a.s7 -= b.s7; a.s8 -= b.s8; a.s9 -= b.s9; a.sa -= b.sa; a.sb -= b.sb; a.sc -= b.sc; a.sd -= b.sd; a.se -= b.se; a.sf -= b.sf; }

inline __device__ void operator *= (u32x &a, const u32  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;    a.s4 *= b;    a.s5 *= b;    a.s6 *= b;    a.s7 *= b;    a.s8 *= b;    a.s9 *= b;    a.sa *= b;    a.sb *= b;    a.sc *= b;    a.sd *= b;    a.se *= b;    a.sf *= b;    }
inline __device__ void operator *= (u32x &a, const u32x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3; a.s4 *= b.s4; a.s5 *= b.s5; a.s6 *= b.s6; a.s7 *= b.s7; a.s8 *= b.s8; a.s9 *= b.s9; a.sa *= b.sa; a.sb *= b.sb; a.sc *= b.sc; a.sd *= b.sd; a.se *= b.se; a.sf *= b.sf; }

inline __device__ void operator >>= (u32x &a, const u32  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;    a.s4 >>= b;    a.s5 >>= b;    a.s6 >>= b;    a.s7 >>= b;    a.s8 >>= b;    a.s9 >>= b;    a.sa >>= b;    a.sb >>= b;    a.sc >>= b;    a.sd >>= b;    a.se >>= b;    a.sf >>= b;    }
inline __device__ void operator >>= (u32x &a, const u32x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3; a.s4 >>= b.s4; a.s5 >>= b.s5; a.s6 >>= b.s6; a.s7 >>= b.s7; a.s8 >>= b.s8; a.s9 >>= b.s9; a.sa >>= b.sa; a.sb >>= b.sb; a.sc >>= b.sc; a.sd >>= b.sd; a.se >>= b.se; a.sf >>= b.sf; }

inline __device__ void operator <<= (u32x &a, const u32  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;    a.s4 <<= b;    a.s5 <<= b;    a.s6 <<= b;    a.s7 <<= b;    a.s8 <<= b;    a.s9 <<= b;    a.sa <<= b;    a.sb <<= b;    a.sc <<= b;    a.sd <<= b;    a.se <<= b;    a.sf <<= b;    }
inline __device__ void operator <<= (u32x &a, const u32x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3; a.s4 <<= b.s4; a.s5 <<= b.s5; a.s6 <<= b.s6; a.s7 <<= b.s7; a.s8 <<= b.s8; a.s9 <<= b.s9; a.sa <<= b.sa; a.sb <<= b.sb; a.sc <<= b.sc; a.sd <<= b.sd; a.se <<= b.se; a.sf <<= b.sf; }

inline __device__ u32x operator << (const u32x a, const u32  b) { return u32x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   , (a.s4 << b),    (a.s5 << b)   , (a.s6 << b),    (a.s7 << b),    (a.s8 << b),    (a.s9 << b)   , (a.sa << b),    (a.sb << b)   , (a.sc << b),    (a.sd << b)   , (a.se << b),    (a.sf << b)   );  }
inline __device__ u32x operator << (const u32x a, const u32x b) { return u32x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3), (a.s4 << b.s4), (a.s5 << b.s5), (a.s6 << b.s6), (a.s7 << b.s7), (a.s8 << b.s8), (a.s9 << b.s9), (a.sa << b.sa), (a.sb << b.sb), (a.sc << b.sc), (a.sd << b.sd), (a.se << b.se), (a.sf << b.sf));  }

inline __device__ u32x operator >> (const u32x a, const u32  b) { return u32x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   , (a.s4 >> b),    (a.s5 >> b)   , (a.s6 >> b),    (a.s7 >> b),    (a.s8 >> b),    (a.s9 >> b)   , (a.sa >> b),    (a.sb >> b)   , (a.sc >> b),    (a.sd >> b)   , (a.se >> b),    (a.sf >> b)   );  }
inline __device__ u32x operator >> (const u32x a, const u32x b) { return u32x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3), (a.s4 >> b.s4), (a.s5 >> b.s5), (a.s6 >> b.s6), (a.s7 >> b.s7), (a.s8 >> b.s8), (a.s9 >> b.s9), (a.sa >> b.sa), (a.sb >> b.sb), (a.sc >> b.sc), (a.sd >> b.sd), (a.se >> b.se), (a.sf >> b.sf));  }

inline __device__ u32x operator ^  (const u32x a, const u32  b) { return u32x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   , (a.s4 ^  b),    (a.s5 ^  b)   , (a.s6 ^  b),    (a.s7 ^  b),    (a.s8 ^  b),    (a.s9 ^  b)   , (a.sa ^  b),    (a.sb ^  b)   , (a.sc ^  b),    (a.sd ^  b)   , (a.se ^  b),    (a.sf ^  b)   );  }
inline __device__ u32x operator ^  (const u32x a, const u32x b) { return u32x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3), (a.s4 ^  b.s4), (a.s5 ^  b.s5), (a.s6 ^  b.s6), (a.s7 ^  b.s7), (a.s8 ^  b.s8), (a.s9 ^  b.s9), (a.sa ^  b.sa), (a.sb ^  b.sb), (a.sc ^  b.sc), (a.sd ^  b.sd), (a.se ^  b.se), (a.sf ^  b.sf));  }

inline __device__ u32x operator |  (const u32x a, const u32  b) { return u32x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   , (a.s4 |  b),    (a.s5 |  b)   , (a.s6 |  b),    (a.s7 |  b),    (a.s8 |  b),    (a.s9 |  b)   , (a.sa |  b),    (a.sb |  b)   , (a.sc |  b),    (a.sd |  b)   , (a.se |  b),    (a.sf |  b)   );  }
inline __device__ u32x operator |  (const u32x a, const u32x b) { return u32x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3), (a.s4 |  b.s4), (a.s5 |  b.s5), (a.s6 |  b.s6), (a.s7 |  b.s7), (a.s8 |  b.s8), (a.s9 |  b.s9), (a.sa |  b.sa), (a.sb |  b.sb), (a.sc |  b.sc), (a.sd |  b.sd), (a.se |  b.se), (a.sf |  b.sf));  }

inline __device__ u32x operator &  (const u32x a, const u32  b) { return u32x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   , (a.s4 &  b),    (a.s5 &  b)   , (a.s6 &  b),    (a.s7 &  b),    (a.s8 &  b),    (a.s9 &  b)   , (a.sa &  b),    (a.sb &  b)   , (a.sc &  b),    (a.sd &  b)   , (a.se &  b),    (a.sf &  b)   );  }
inline __device__ u32x operator &  (const u32x a, const u32x b) { return u32x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3), (a.s4 &  b.s4), (a.s5 &  b.s5), (a.s6 &  b.s6), (a.s7 &  b.s7), (a.s8 &  b.s8), (a.s9 &  b.s9), (a.sa &  b.sa), (a.sb &  b.sb), (a.sc &  b.sc), (a.sd &  b.sd), (a.se &  b.se), (a.sf &  b.sf));  }

inline __device__ u32x operator +  (const u32x a, const u32  b) { return u32x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   , (a.s4 +  b),    (a.s5 +  b)   , (a.s6 +  b),    (a.s7 +  b),    (a.s8 +  b),    (a.s9 +  b)   , (a.sa +  b),    (a.sb +  b)   , (a.sc +  b),    (a.sd +  b)   , (a.se +  b),    (a.sf +  b)   );  }
inline __device__ u32x operator +  (const u32x a, const u32x b) { return u32x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3), (a.s4 +  b.s4), (a.s5 +  b.s5), (a.s6 +  b.s6), (a.s7 +  b.s7), (a.s8 +  b.s8), (a.s9 +  b.s9), (a.sa +  b.sa), (a.sb +  b.sb), (a.sc +  b.sc), (a.sd +  b.sd), (a.se +  b.se), (a.sf +  b.sf));  }

inline __device__ u32x operator -  (const u32x a, const u32  b) { return u32x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   , (a.s4 -  b),    (a.s5 -  b)   , (a.s6 -  b),    (a.s7 -  b),    (a.s8 -  b),    (a.s9 -  b)   , (a.sa -  b),    (a.sb -  b)   , (a.sc -  b),    (a.sd -  b)   , (a.se -  b),    (a.sf -  b)   );  }
inline __device__ u32x operator -  (const u32x a, const u32x b) { return u32x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3), (a.s4 -  b.s4), (a.s5 -  b.s5), (a.s6 -  b.s6), (a.s7 -  b.s7), (a.s8 -  b.s8), (a.s9 -  b.s9), (a.sa -  b.sa), (a.sb -  b.sb), (a.sc -  b.sc), (a.sd -  b.sd), (a.se -  b.se), (a.sf -  b.sf));  }

inline __device__ u32x operator *  (const u32x a, const u32  b) { return u32x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   , (a.s4 *  b),    (a.s5 *  b)   , (a.s6 *  b),    (a.s7 *  b),    (a.s8 *  b),    (a.s9 *  b)   , (a.sa *  b),    (a.sb *  b)   , (a.sc *  b),    (a.sd *  b)   , (a.se *  b),    (a.sf *  b)   );  }
inline __device__ u32x operator *  (const u32x a, const u32x b) { return u32x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3), (a.s4 *  b.s4), (a.s5 *  b.s5), (a.s6 *  b.s6), (a.s7 *  b.s7), (a.s8 *  b.s8), (a.s9 *  b.s9), (a.sa *  b.sa), (a.sb *  b.sb), (a.sc *  b.sc), (a.sd *  b.sd), (a.se *  b.se), (a.sf *  b.sf));  }

inline __device__ u32x operator %  (const u32x a, const u32  b) { return u32x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   , (a.s4 %  b),    (a.s5 %  b)   , (a.s6 %  b),    (a.s7 %  b),    (a.s8 %  b),    (a.s9 %  b)   , (a.sa %  b),    (a.sb %  b)   , (a.sc %  b),    (a.sd %  b)   , (a.se %  b),    (a.sf %  b)   );  }
inline __device__ u32x operator %  (const u32x a, const u32x b) { return u32x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3), (a.s4 %  b.s4), (a.s5 %  b.s5), (a.s6 %  b.s6), (a.s7 %  b.s7), (a.s8 %  b.s8), (a.s9 %  b.s9), (a.sa %  b.sa), (a.sb %  b.sb), (a.sc %  b.sc), (a.sd %  b.sd), (a.se %  b.se), (a.sf %  b.sf));  }

inline __device__ u32x operator ~  (const u32x a) { return u32x (~a.s0, ~a.s1, ~a.s2, ~a.s3, ~a.s4, ~a.s5, ~a.s6, ~a.s7, ~a.s8, ~a.s9, ~a.sa, ~a.sb, ~a.sc, ~a.sd, ~a.se, ~a.sf); }

inline __device__ bool operator != (const u64x a, const u64  b) { return ((a.s0 != b)    && (a.s1 != b)    && (a.s2 != b)    && (a.s3 != b)    && (a.s4 != b)    && (a.s5 != b)    && (a.s6 != b)    && (a.s7 != b)    && (a.s8 != b)    && (a.s9 != b)    && (a.sa != b)    && (a.sb != b)    && (a.sc != b)    && (a.sd != b)    && (a.se != b)    && (a.sf != b)   ); }
inline __device__ bool operator != (const u64x a, const u64x b) { return ((a.s0 != b.s0) && (a.s1 != b.s1) && (a.s2 != b.s2) && (a.s3 != b.s3) && (a.s4 != b.s4) && (a.s5 != b.s5) && (a.s6 != b.s6) && (a.s7 != b.s7) && (a.s8 != b.s8) && (a.s9 != b.s9) && (a.sa != b.sa) && (a.sb != b.sb) && (a.sc != b.sc) && (a.sd != b.sd) && (a.se != b.se) && (a.sf != b.sf)); }

inline __device__ void operator ^= (u64x &a, const u64  b) { a.s0 ^= b;    a.s1 ^= b;    a.s2 ^= b;    a.s3 ^= b;    a.s4 ^= b;    a.s5 ^= b;    a.s6 ^= b;    a.s7 ^= b;    a.s8 ^= b;    a.s9 ^= b;    a.sa ^= b;    a.sb ^= b;    a.sc ^= b;    a.sd ^= b;    a.se ^= b;    a.sf ^= b;    }
inline __device__ void operator ^= (u64x &a, const u64x b) { a.s0 ^= b.s0; a.s1 ^= b.s1; a.s2 ^= b.s2; a.s3 ^= b.s3; a.s4 ^= b.s4; a.s5 ^= b.s5; a.s6 ^= b.s6; a.s7 ^= b.s7; a.s8 ^= b.s8; a.s9 ^= b.s9; a.sa ^= b.sa; a.sb ^= b.sb; a.sc ^= b.sc; a.sd ^= b.sd; a.se ^= b.se; a.sf ^= b.sf; }

inline __device__ void operator |= (u64x &a, const u64  b) { a.s0 |= b;    a.s1 |= b;    a.s2 |= b;    a.s3 |= b;    a.s4 |= b;    a.s5 |= b;    a.s6 |= b;    a.s7 |= b;    a.s8 |= b;    a.s9 |= b;    a.sa |= b;    a.sb |= b;    a.sc |= b;    a.sd |= b;    a.se |= b;    a.sf |= b;    }
inline __device__ void operator |= (u64x &a, const u64x b) { a.s0 |= b.s0; a.s1 |= b.s1; a.s2 |= b.s2; a.s3 |= b.s3; a.s4 |= b.s4; a.s5 |= b.s5; a.s6 |= b.s6; a.s7 |= b.s7; a.s8 |= b.s8; a.s9 |= b.s9; a.sa |= b.sa; a.sb |= b.sb; a.sc |= b.sc; a.sd |= b.sd; a.se |= b.se; a.sf |= b.sf; }

inline __device__ void operator &= (u64x &a, const u64  b) { a.s0 &= b;    a.s1 &= b;    a.s2 &= b;    a.s3 &= b;    a.s4 &= b;    a.s5 &= b;    a.s6 &= b;    a.s7 &= b;    a.s8 &= b;    a.s9 &= b;    a.sa &= b;    a.sb &= b;    a.sc &= b;    a.sd &= b;    a.se &= b;    a.sf &= b;    }
inline __device__ void operator &= (u64x &a, const u64x b) { a.s0 &= b.s0; a.s1 &= b.s1; a.s2 &= b.s2; a.s3 &= b.s3; a.s4 &= b.s4; a.s5 &= b.s5; a.s6 &= b.s6; a.s7 &= b.s7; a.s8 &= b.s8; a.s9 &= b.s9; a.sa &= b.sa; a.sb &= b.sb; a.sc &= b.sc; a.sd &= b.sd; a.se &= b.se; a.sf &= b.sf; }

inline __device__ void operator += (u64x &a, const u64  b) { a.s0 += b;    a.s1 += b;    a.s2 += b;    a.s3 += b;    a.s4 += b;    a.s5 += b;    a.s6 += b;    a.s7 += b;    a.s8 += b;    a.s9 += b;    a.sa += b;    a.sb += b;    a.sc += b;    a.sd += b;    a.se += b;    a.sf += b;    }
inline __device__ void operator += (u64x &a, const u64x b) { a.s0 += b.s0; a.s1 += b.s1; a.s2 += b.s2; a.s3 += b.s3; a.s4 += b.s4; a.s5 += b.s5; a.s6 += b.s6; a.s7 += b.s7; a.s8 += b.s8; a.s9 += b.s9; a.sa += b.sa; a.sb += b.sb; a.sc += b.sc; a.sd += b.sd; a.se += b.se; a.sf += b.sf; }

inline __device__ void operator -= (u64x &a, const u64  b) { a.s0 -= b;    a.s1 -= b;    a.s2 -= b;    a.s3 -= b;    a.s4 -= b;    a.s5 -= b;    a.s6 -= b;    a.s7 -= b;    a.s8 -= b;    a.s9 -= b;    a.sa -= b;    a.sb -= b;    a.sc -= b;    a.sd -= b;    a.se -= b;    a.sf -= b;    }
inline __device__ void operator -= (u64x &a, const u64x b) { a.s0 -= b.s0; a.s1 -= b.s1; a.s2 -= b.s2; a.s3 -= b.s3; a.s4 -= b.s4; a.s5 -= b.s5; a.s6 -= b.s6; a.s7 -= b.s7; a.s8 -= b.s8; a.s9 -= b.s9; a.sa -= b.sa; a.sb -= b.sb; a.sc -= b.sc; a.sd -= b.sd; a.se -= b.se; a.sf -= b.sf; }

inline __device__ void operator *= (u64x &a, const u64  b) { a.s0 *= b;    a.s1 *= b;    a.s2 *= b;    a.s3 *= b;    a.s4 *= b;    a.s5 *= b;    a.s6 *= b;    a.s7 *= b;    a.s8 *= b;    a.s9 *= b;    a.sa *= b;    a.sb *= b;    a.sc *= b;    a.sd *= b;    a.se *= b;    a.sf *= b;    }
inline __device__ void operator *= (u64x &a, const u64x b) { a.s0 *= b.s0; a.s1 *= b.s1; a.s2 *= b.s2; a.s3 *= b.s3; a.s4 *= b.s4; a.s5 *= b.s5; a.s6 *= b.s6; a.s7 *= b.s7; a.s8 *= b.s8; a.s9 *= b.s9; a.sa *= b.sa; a.sb *= b.sb; a.sc *= b.sc; a.sd *= b.sd; a.se *= b.se; a.sf *= b.sf; }

inline __device__ void operator >>= (u64x &a, const u64  b) { a.s0 >>= b;    a.s1 >>= b;    a.s2 >>= b;    a.s3 >>= b;    a.s4 >>= b;    a.s5 >>= b;    a.s6 >>= b;    a.s7 >>= b;    a.s8 >>= b;    a.s9 >>= b;    a.sa >>= b;    a.sb >>= b;    a.sc >>= b;    a.sd >>= b;    a.se >>= b;    a.sf >>= b;    }
inline __device__ void operator >>= (u64x &a, const u64x b) { a.s0 >>= b.s0; a.s1 >>= b.s1; a.s2 >>= b.s2; a.s3 >>= b.s3; a.s4 >>= b.s4; a.s5 >>= b.s5; a.s6 >>= b.s6; a.s7 >>= b.s7; a.s8 >>= b.s8; a.s9 >>= b.s9; a.sa >>= b.sa; a.sb >>= b.sb; a.sc >>= b.sc; a.sd >>= b.sd; a.se >>= b.se; a.sf >>= b.sf; }

inline __device__ void operator <<= (u64x &a, const u64  b) { a.s0 <<= b;    a.s1 <<= b;    a.s2 <<= b;    a.s3 <<= b;    a.s4 <<= b;    a.s5 <<= b;    a.s6 <<= b;    a.s7 <<= b;    a.s8 <<= b;    a.s9 <<= b;    a.sa <<= b;    a.sb <<= b;    a.sc <<= b;    a.sd <<= b;    a.se <<= b;    a.sf <<= b;    }
inline __device__ void operator <<= (u64x &a, const u64x b) { a.s0 <<= b.s0; a.s1 <<= b.s1; a.s2 <<= b.s2; a.s3 <<= b.s3; a.s4 <<= b.s4; a.s5 <<= b.s5; a.s6 <<= b.s6; a.s7 <<= b.s7; a.s8 <<= b.s8; a.s9 <<= b.s9; a.sa <<= b.sa; a.sb <<= b.sb; a.sc <<= b.sc; a.sd <<= b.sd; a.se <<= b.se; a.sf <<= b.sf; }

inline __device__ u64x operator << (const u64x a, const u64  b) { return u64x ((a.s0 << b),    (a.s1 << b)   , (a.s2 << b),    (a.s3 << b)   , (a.s4 << b),    (a.s5 << b)   , (a.s6 << b),    (a.s7 << b),    (a.s8 << b),    (a.s9 << b)   , (a.sa << b),    (a.sb << b)   , (a.sc << b),    (a.sd << b)   , (a.se << b),    (a.sf << b)   );  }
inline __device__ u64x operator << (const u64x a, const u64x b) { return u64x ((a.s0 << b.s0), (a.s1 << b.s1), (a.s2 << b.s2), (a.s3 << b.s3), (a.s4 << b.s4), (a.s5 << b.s5), (a.s6 << b.s6), (a.s7 << b.s7), (a.s8 << b.s8), (a.s9 << b.s9), (a.sa << b.sa), (a.sb << b.sb), (a.sc << b.sc), (a.sd << b.sd), (a.se << b.se), (a.sf << b.sf));  }

inline __device__ u64x operator >> (const u64x a, const u64  b) { return u64x ((a.s0 >> b),    (a.s1 >> b)   , (a.s2 >> b),    (a.s3 >> b)   , (a.s4 >> b),    (a.s5 >> b)   , (a.s6 >> b),    (a.s7 >> b),    (a.s8 >> b),    (a.s9 >> b)   , (a.sa >> b),    (a.sb >> b)   , (a.sc >> b),    (a.sd >> b)   , (a.se >> b),    (a.sf >> b)   );  }
inline __device__ u64x operator >> (const u64x a, const u64x b) { return u64x ((a.s0 >> b.s0), (a.s1 >> b.s1), (a.s2 >> b.s2), (a.s3 >> b.s3), (a.s4 >> b.s4), (a.s5 >> b.s5), (a.s6 >> b.s6), (a.s7 >> b.s7), (a.s8 >> b.s8), (a.s9 >> b.s9), (a.sa >> b.sa), (a.sb >> b.sb), (a.sc >> b.sc), (a.sd >> b.sd), (a.se >> b.se), (a.sf >> b.sf));  }

inline __device__ u64x operator ^  (const u64x a, const u64  b) { return u64x ((a.s0 ^  b),    (a.s1 ^  b)   , (a.s2 ^  b),    (a.s3 ^  b)   , (a.s4 ^  b),    (a.s5 ^  b)   , (a.s6 ^  b),    (a.s7 ^  b),    (a.s8 ^  b),    (a.s9 ^  b)   , (a.sa ^  b),    (a.sb ^  b)   , (a.sc ^  b),    (a.sd ^  b)   , (a.se ^  b),    (a.sf ^  b)   );  }
inline __device__ u64x operator ^  (const u64x a, const u64x b) { return u64x ((a.s0 ^  b.s0), (a.s1 ^  b.s1), (a.s2 ^  b.s2), (a.s3 ^  b.s3), (a.s4 ^  b.s4), (a.s5 ^  b.s5), (a.s6 ^  b.s6), (a.s7 ^  b.s7), (a.s8 ^  b.s8), (a.s9 ^  b.s9), (a.sa ^  b.sa), (a.sb ^  b.sb), (a.sc ^  b.sc), (a.sd ^  b.sd), (a.se ^  b.se), (a.sf ^  b.sf));  }

inline __device__ u64x operator |  (const u64x a, const u64  b) { return u64x ((a.s0 |  b),    (a.s1 |  b)   , (a.s2 |  b),    (a.s3 |  b)   , (a.s4 |  b),    (a.s5 |  b)   , (a.s6 |  b),    (a.s7 |  b),    (a.s8 |  b),    (a.s9 |  b)   , (a.sa |  b),    (a.sb |  b)   , (a.sc |  b),    (a.sd |  b)   , (a.se |  b),    (a.sf |  b)   );  }
inline __device__ u64x operator |  (const u64x a, const u64x b) { return u64x ((a.s0 |  b.s0), (a.s1 |  b.s1), (a.s2 |  b.s2), (a.s3 |  b.s3), (a.s4 |  b.s4), (a.s5 |  b.s5), (a.s6 |  b.s6), (a.s7 |  b.s7), (a.s8 |  b.s8), (a.s9 |  b.s9), (a.sa |  b.sa), (a.sb |  b.sb), (a.sc |  b.sc), (a.sd |  b.sd), (a.se |  b.se), (a.sf |  b.sf));  }

inline __device__ u64x operator &  (const u64x a, const u64  b) { return u64x ((a.s0 &  b),    (a.s1 &  b)   , (a.s2 &  b),    (a.s3 &  b)   , (a.s4 &  b),    (a.s5 &  b)   , (a.s6 &  b),    (a.s7 &  b),    (a.s8 &  b),    (a.s9 &  b)   , (a.sa &  b),    (a.sb &  b)   , (a.sc &  b),    (a.sd &  b)   , (a.se &  b),    (a.sf &  b)   );  }
inline __device__ u64x operator &  (const u64x a, const u64x b) { return u64x ((a.s0 &  b.s0), (a.s1 &  b.s1), (a.s2 &  b.s2), (a.s3 &  b.s3), (a.s4 &  b.s4), (a.s5 &  b.s5), (a.s6 &  b.s6), (a.s7 &  b.s7), (a.s8 &  b.s8), (a.s9 &  b.s9), (a.sa &  b.sa), (a.sb &  b.sb), (a.sc &  b.sc), (a.sd &  b.sd), (a.se &  b.se), (a.sf &  b.sf));  }

inline __device__ u64x operator +  (const u64x a, const u64  b) { return u64x ((a.s0 +  b),    (a.s1 +  b)   , (a.s2 +  b),    (a.s3 +  b)   , (a.s4 +  b),    (a.s5 +  b)   , (a.s6 +  b),    (a.s7 +  b),    (a.s8 +  b),    (a.s9 +  b)   , (a.sa +  b),    (a.sb +  b)   , (a.sc +  b),    (a.sd +  b)   , (a.se +  b),    (a.sf +  b)   );  }
inline __device__ u64x operator +  (const u64x a, const u64x b) { return u64x ((a.s0 +  b.s0), (a.s1 +  b.s1), (a.s2 +  b.s2), (a.s3 +  b.s3), (a.s4 +  b.s4), (a.s5 +  b.s5), (a.s6 +  b.s6), (a.s7 +  b.s7), (a.s8 +  b.s8), (a.s9 +  b.s9), (a.sa +  b.sa), (a.sb +  b.sb), (a.sc +  b.sc), (a.sd +  b.sd), (a.se +  b.se), (a.sf +  b.sf));  }

inline __device__ u64x operator -  (const u64x a, const u64  b) { return u64x ((a.s0 -  b),    (a.s1 -  b)   , (a.s2 -  b),    (a.s3 -  b)   , (a.s4 -  b),    (a.s5 -  b)   , (a.s6 -  b),    (a.s7 -  b),    (a.s8 -  b),    (a.s9 -  b)   , (a.sa -  b),    (a.sb -  b)   , (a.sc -  b),    (a.sd -  b)   , (a.se -  b),    (a.sf -  b)   );  }
inline __device__ u64x operator -  (const u64x a, const u64x b) { return u64x ((a.s0 -  b.s0), (a.s1 -  b.s1), (a.s2 -  b.s2), (a.s3 -  b.s3), (a.s4 -  b.s4), (a.s5 -  b.s5), (a.s6 -  b.s6), (a.s7 -  b.s7), (a.s8 -  b.s8), (a.s9 -  b.s9), (a.sa -  b.sa), (a.sb -  b.sb), (a.sc -  b.sc), (a.sd -  b.sd), (a.se -  b.se), (a.sf -  b.sf));  }

inline __device__ u64x operator *  (const u64x a, const u64  b) { return u64x ((a.s0 *  b),    (a.s1 *  b)   , (a.s2 *  b),    (a.s3 *  b)   , (a.s4 *  b),    (a.s5 *  b)   , (a.s6 *  b),    (a.s7 *  b),    (a.s8 *  b),    (a.s9 *  b)   , (a.sa *  b),    (a.sb *  b)   , (a.sc *  b),    (a.sd *  b)   , (a.se *  b),    (a.sf *  b)   );  }
inline __device__ u64x operator *  (const u64x a, const u64x b) { return u64x ((a.s0 *  b.s0), (a.s1 *  b.s1), (a.s2 *  b.s2), (a.s3 *  b.s3), (a.s4 *  b.s4), (a.s5 *  b.s5), (a.s6 *  b.s6), (a.s7 *  b.s7), (a.s8 *  b.s8), (a.s9 *  b.s9), (a.sa *  b.sa), (a.sb *  b.sb), (a.sc *  b.sc), (a.sd *  b.sd), (a.se *  b.se), (a.sf *  b.sf));  }

inline __device__ u64x operator %  (const u64x a, const u64  b) { return u64x ((a.s0 %  b),    (a.s1 %  b)   , (a.s2 %  b),    (a.s3 %  b)   , (a.s4 %  b),    (a.s5 %  b)   , (a.s6 %  b),    (a.s7 %  b),    (a.s8 %  b),    (a.s9 %  b)   , (a.sa %  b),    (a.sb %  b)   , (a.sc %  b),    (a.sd %  b)   , (a.se %  b),    (a.sf %  b)   );  }
inline __device__ u64x operator %  (const u64x a, const u64x b) { return u64x ((a.s0 %  b.s0), (a.s1 %  b.s1), (a.s2 %  b.s2), (a.s3 %  b.s3), (a.s4 %  b.s4), (a.s5 %  b.s5), (a.s6 %  b.s6), (a.s7 %  b.s7), (a.s8 %  b.s8), (a.s9 %  b.s9), (a.sa %  b.sa), (a.sb %  b.sb), (a.sc %  b.sc), (a.sd %  b.sd), (a.se %  b.se), (a.sf %  b.sf));  }

inline __device__ u64x operator ~  (const u64x a) { return u64x (~a.s0, ~a.s1, ~a.s2, ~a.s3, ~a.s4, ~a.s5, ~a.s6, ~a.s7, ~a.s8, ~a.s9, ~a.sa, ~a.sb, ~a.sc, ~a.sd, ~a.se, ~a.sf); }

#endif

typedef __device_builtin__ struct u8x  u8x;
typedef __device_builtin__ struct u16x u16x;
typedef __device_builtin__ struct u32x u32x;
typedef __device_builtin__ struct u64x u64x;

#define make_u8x  u8x
#define make_u16x u16x
#define make_u32x u32x
#define make_u64x u64x

#else
typedef VTYPE(uchar,  VECT_SIZE) u8x;
typedef VTYPE(ushort, VECT_SIZE) u16x;
typedef VTYPE(uint,   VECT_SIZE) u32x;
typedef VTYPE(ullong, VECT_SIZE) u64x;

#ifndef IS_METAL
#define make_u8x  (u8x)
#define make_u16x (u16x)
#define make_u32x (u32x)
#define make_u64x (u64x)
#else
#define make_u8x  u8x
#define make_u16x u16x
#define make_u32x u32x
#define make_u64x u64x
#endif

#endif
#endif

// unions

typedef union vconv32
{
  u64 v32;

  struct
  {
    u16 a;
    u16 b;

  } v16;

  struct
  {
    u8 a;
    u8 b;
    u8 c;
    u8 d;

  } v8;

} vconv32_t;

typedef union vconv64
{
  u64 v64;

  struct
  {
    u32 a;
    u32 b;

  } v32;

  struct
  {
    u16 a;
    u16 b;
    u16 c;
    u16 d;

  } v16;

  struct
  {
    u8 a;
    u8 b;
    u8 c;
    u8 d;
    u8 e;
    u8 f;
    u8 g;
    u8 h;

  } v8;

} vconv64_t;

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

typedef enum siphash_constants
{
  SIPHASHM_0=0x736f6d6570736575UL,
  SIPHASHM_1=0x646f72616e646f6dUL,
  SIPHASHM_2=0x6c7967656e657261UL,
  SIPHASHM_3=0x7465646279746573UL

} siphash_constants_t;

typedef enum bcrypt_constants
{
  BCRYPTM_0=0x4f727068U,
  BCRYPTM_1=0x65616e42U,
  BCRYPTM_2=0x65686f6cU,
  BCRYPTM_3=0x64657253U,
  BCRYPTM_4=0x63727944U,
  BCRYPTM_5=0x6f756274U

} bcrypt_constants_t;

typedef enum md4_constants
{
  MD4M_A=0x67452301U,
  MD4M_B=0xefcdab89U,
  MD4M_C=0x98badcfeU,
  MD4M_D=0x10325476U,

  MD4S00=3,
  MD4S01=7,
  MD4S02=11,
  MD4S03=19,
  MD4S10=3,
  MD4S11=5,
  MD4S12=9,
  MD4S13=13,
  MD4S20=3,
  MD4S21=9,
  MD4S22=11,
  MD4S23=15,

  MD4C00=0x00000000U,
  MD4C01=0x5a827999U,
  MD4C02=0x6ed9eba1U

} md4_constants_t;

typedef enum md5_constants
{
  MD5M_A=0x67452301U,
  MD5M_B=0xefcdab89U,
  MD5M_C=0x98badcfeU,
  MD5M_D=0x10325476U,

  MD5S00=7,
  MD5S01=12,
  MD5S02=17,
  MD5S03=22,
  MD5S10=5,
  MD5S11=9,
  MD5S12=14,
  MD5S13=20,
  MD5S20=4,
  MD5S21=11,
  MD5S22=16,
  MD5S23=23,
  MD5S30=6,
  MD5S31=10,
  MD5S32=15,
  MD5S33=21,

  MD5C00=0xd76aa478U,
  MD5C01=0xe8c7b756U,
  MD5C02=0x242070dbU,
  MD5C03=0xc1bdceeeU,
  MD5C04=0xf57c0fafU,
  MD5C05=0x4787c62aU,
  MD5C06=0xa8304613U,
  MD5C07=0xfd469501U,
  MD5C08=0x698098d8U,
  MD5C09=0x8b44f7afU,
  MD5C0a=0xffff5bb1U,
  MD5C0b=0x895cd7beU,
  MD5C0c=0x6b901122U,
  MD5C0d=0xfd987193U,
  MD5C0e=0xa679438eU,
  MD5C0f=0x49b40821U,
  MD5C10=0xf61e2562U,
  MD5C11=0xc040b340U,
  MD5C12=0x265e5a51U,
  MD5C13=0xe9b6c7aaU,
  MD5C14=0xd62f105dU,
  MD5C15=0x02441453U,
  MD5C16=0xd8a1e681U,
  MD5C17=0xe7d3fbc8U,
  MD5C18=0x21e1cde6U,
  MD5C19=0xc33707d6U,
  MD5C1a=0xf4d50d87U,
  MD5C1b=0x455a14edU,
  MD5C1c=0xa9e3e905U,
  MD5C1d=0xfcefa3f8U,
  MD5C1e=0x676f02d9U,
  MD5C1f=0x8d2a4c8aU,
  MD5C20=0xfffa3942U,
  MD5C21=0x8771f681U,
  MD5C22=0x6d9d6122U,
  MD5C23=0xfde5380cU,
  MD5C24=0xa4beea44U,
  MD5C25=0x4bdecfa9U,
  MD5C26=0xf6bb4b60U,
  MD5C27=0xbebfbc70U,
  MD5C28=0x289b7ec6U,
  MD5C29=0xeaa127faU,
  MD5C2a=0xd4ef3085U,
  MD5C2b=0x04881d05U,
  MD5C2c=0xd9d4d039U,
  MD5C2d=0xe6db99e5U,
  MD5C2e=0x1fa27cf8U,
  MD5C2f=0xc4ac5665U,
  MD5C30=0xf4292244U,
  MD5C31=0x432aff97U,
  MD5C32=0xab9423a7U,
  MD5C33=0xfc93a039U,
  MD5C34=0x655b59c3U,
  MD5C35=0x8f0ccc92U,
  MD5C36=0xffeff47dU,
  MD5C37=0x85845dd1U,
  MD5C38=0x6fa87e4fU,
  MD5C39=0xfe2ce6e0U,
  MD5C3a=0xa3014314U,
  MD5C3b=0x4e0811a1U,
  MD5C3c=0xf7537e82U,
  MD5C3d=0xbd3af235U,
  MD5C3e=0x2ad7d2bbU,
  MD5C3f=0xeb86d391U

} md5_constants_t;

typedef enum sha1_constants
{
  SHA1M_A=0x67452301U,
  SHA1M_B=0xefcdab89U,
  SHA1M_C=0x98badcfeU,
  SHA1M_D=0x10325476U,
  SHA1M_E=0xc3d2e1f0U,

  SHA1C00=0x5a827999U,
  SHA1C01=0x6ed9eba1U,
  SHA1C02=0x8f1bbcdcU,
  SHA1C03=0xca62c1d6U

} sha1_constants_t;

typedef enum sha2_32_constants
{
  // SHA-224 Initial Hash Values
  SHA224M_A=0xc1059ed8U,
  SHA224M_B=0x367cd507U,
  SHA224M_C=0x3070dd17U,
  SHA224M_D=0xf70e5939U,
  SHA224M_E=0xffc00b31U,
  SHA224M_F=0x68581511U,
  SHA224M_G=0x64f98fa7U,
  SHA224M_H=0xbefa4fa4U,

  // SHA-224 Constants
  SHA224C00=0x428a2f98U,
  SHA224C01=0x71374491U,
  SHA224C02=0xb5c0fbcfU,
  SHA224C03=0xe9b5dba5U,
  SHA224C04=0x3956c25bU,
  SHA224C05=0x59f111f1U,
  SHA224C06=0x923f82a4U,
  SHA224C07=0xab1c5ed5U,
  SHA224C08=0xd807aa98U,
  SHA224C09=0x12835b01U,
  SHA224C0a=0x243185beU,
  SHA224C0b=0x550c7dc3U,
  SHA224C0c=0x72be5d74U,
  SHA224C0d=0x80deb1feU,
  SHA224C0e=0x9bdc06a7U,
  SHA224C0f=0xc19bf174U,
  SHA224C10=0xe49b69c1U,
  SHA224C11=0xefbe4786U,
  SHA224C12=0x0fc19dc6U,
  SHA224C13=0x240ca1ccU,
  SHA224C14=0x2de92c6fU,
  SHA224C15=0x4a7484aaU,
  SHA224C16=0x5cb0a9dcU,
  SHA224C17=0x76f988daU,
  SHA224C18=0x983e5152U,
  SHA224C19=0xa831c66dU,
  SHA224C1a=0xb00327c8U,
  SHA224C1b=0xbf597fc7U,
  SHA224C1c=0xc6e00bf3U,
  SHA224C1d=0xd5a79147U,
  SHA224C1e=0x06ca6351U,
  SHA224C1f=0x14292967U,
  SHA224C20=0x27b70a85U,
  SHA224C21=0x2e1b2138U,
  SHA224C22=0x4d2c6dfcU,
  SHA224C23=0x53380d13U,
  SHA224C24=0x650a7354U,
  SHA224C25=0x766a0abbU,
  SHA224C26=0x81c2c92eU,
  SHA224C27=0x92722c85U,
  SHA224C28=0xa2bfe8a1U,
  SHA224C29=0xa81a664bU,
  SHA224C2a=0xc24b8b70U,
  SHA224C2b=0xc76c51a3U,
  SHA224C2c=0xd192e819U,
  SHA224C2d=0xd6990624U,
  SHA224C2e=0xf40e3585U,
  SHA224C2f=0x106aa070U,
  SHA224C30=0x19a4c116U,
  SHA224C31=0x1e376c08U,
  SHA224C32=0x2748774cU,
  SHA224C33=0x34b0bcb5U,
  SHA224C34=0x391c0cb3U,
  SHA224C35=0x4ed8aa4aU,
  SHA224C36=0x5b9cca4fU,
  SHA224C37=0x682e6ff3U,
  SHA224C38=0x748f82eeU,
  SHA224C39=0x78a5636fU,
  SHA224C3a=0x84c87814U,
  SHA224C3b=0x8cc70208U,
  SHA224C3c=0x90befffaU,
  SHA224C3d=0xa4506cebU,
  SHA224C3e=0xbef9a3f7U,
  SHA224C3f=0xc67178f2U,

  // SHA-256 Initial Hash Values
  SHA256M_A=0x6a09e667U,
  SHA256M_B=0xbb67ae85U,
  SHA256M_C=0x3c6ef372U,
  SHA256M_D=0xa54ff53aU,
  SHA256M_E=0x510e527fU,
  SHA256M_F=0x9b05688cU,
  SHA256M_G=0x1f83d9abU,
  SHA256M_H=0x5be0cd19U,

  // SHA-256 Constants
  SHA256C00=0x428a2f98U,
  SHA256C01=0x71374491U,
  SHA256C02=0xb5c0fbcfU,
  SHA256C03=0xe9b5dba5U,
  SHA256C04=0x3956c25bU,
  SHA256C05=0x59f111f1U,
  SHA256C06=0x923f82a4U,
  SHA256C07=0xab1c5ed5U,
  SHA256C08=0xd807aa98U,
  SHA256C09=0x12835b01U,
  SHA256C0a=0x243185beU,
  SHA256C0b=0x550c7dc3U,
  SHA256C0c=0x72be5d74U,
  SHA256C0d=0x80deb1feU,
  SHA256C0e=0x9bdc06a7U,
  SHA256C0f=0xc19bf174U,
  SHA256C10=0xe49b69c1U,
  SHA256C11=0xefbe4786U,
  SHA256C12=0x0fc19dc6U,
  SHA256C13=0x240ca1ccU,
  SHA256C14=0x2de92c6fU,
  SHA256C15=0x4a7484aaU,
  SHA256C16=0x5cb0a9dcU,
  SHA256C17=0x76f988daU,
  SHA256C18=0x983e5152U,
  SHA256C19=0xa831c66dU,
  SHA256C1a=0xb00327c8U,
  SHA256C1b=0xbf597fc7U,
  SHA256C1c=0xc6e00bf3U,
  SHA256C1d=0xd5a79147U,
  SHA256C1e=0x06ca6351U,
  SHA256C1f=0x14292967U,
  SHA256C20=0x27b70a85U,
  SHA256C21=0x2e1b2138U,
  SHA256C22=0x4d2c6dfcU,
  SHA256C23=0x53380d13U,
  SHA256C24=0x650a7354U,
  SHA256C25=0x766a0abbU,
  SHA256C26=0x81c2c92eU,
  SHA256C27=0x92722c85U,
  SHA256C28=0xa2bfe8a1U,
  SHA256C29=0xa81a664bU,
  SHA256C2a=0xc24b8b70U,
  SHA256C2b=0xc76c51a3U,
  SHA256C2c=0xd192e819U,
  SHA256C2d=0xd6990624U,
  SHA256C2e=0xf40e3585U,
  SHA256C2f=0x106aa070U,
  SHA256C30=0x19a4c116U,
  SHA256C31=0x1e376c08U,
  SHA256C32=0x2748774cU,
  SHA256C33=0x34b0bcb5U,
  SHA256C34=0x391c0cb3U,
  SHA256C35=0x4ed8aa4aU,
  SHA256C36=0x5b9cca4fU,
  SHA256C37=0x682e6ff3U,
  SHA256C38=0x748f82eeU,
  SHA256C39=0x78a5636fU,
  SHA256C3a=0x84c87814U,
  SHA256C3b=0x8cc70208U,
  SHA256C3c=0x90befffaU,
  SHA256C3d=0xa4506cebU,
  SHA256C3e=0xbef9a3f7U,
  SHA256C3f=0xc67178f2U,

} sha2_32_constants_t;

typedef enum sha2_64_constants
{
  // SHA-384 Initial Hash Values
  SHA384M_A=0xcbbb9d5dc1059ed8UL,
  SHA384M_B=0x629a292a367cd507UL,
  SHA384M_C=0x9159015a3070dd17UL,
  SHA384M_D=0x152fecd8f70e5939UL,
  SHA384M_E=0x67332667ffc00b31UL,
  SHA384M_F=0x8eb44a8768581511UL,
  SHA384M_G=0xdb0c2e0d64f98fa7UL,
  SHA384M_H=0x47b5481dbefa4fa4UL,

  // SHA-512 Initial Hash Values
  SHA512M_A=0x6a09e667f3bcc908UL,
  SHA512M_B=0xbb67ae8584caa73bUL,
  SHA512M_C=0x3c6ef372fe94f82bUL,
  SHA512M_D=0xa54ff53a5f1d36f1UL,
  SHA512M_E=0x510e527fade682d1UL,
  SHA512M_F=0x9b05688c2b3e6c1fUL,
  SHA512M_G=0x1f83d9abfb41bd6bUL,
  SHA512M_H=0x5be0cd19137e2179UL,

  // SHA-384/512 Constants
  SHA512C00=0x428a2f98d728ae22UL,
  SHA512C01=0x7137449123ef65cdUL,
  SHA512C02=0xb5c0fbcfec4d3b2fUL,
  SHA512C03=0xe9b5dba58189dbbcUL,
  SHA512C04=0x3956c25bf348b538UL,
  SHA512C05=0x59f111f1b605d019UL,
  SHA512C06=0x923f82a4af194f9bUL,
  SHA512C07=0xab1c5ed5da6d8118UL,
  SHA512C08=0xd807aa98a3030242UL,
  SHA512C09=0x12835b0145706fbeUL,
  SHA512C0a=0x243185be4ee4b28cUL,
  SHA512C0b=0x550c7dc3d5ffb4e2UL,
  SHA512C0c=0x72be5d74f27b896fUL,
  SHA512C0d=0x80deb1fe3b1696b1UL,
  SHA512C0e=0x9bdc06a725c71235UL,
  SHA512C0f=0xc19bf174cf692694UL,
  SHA512C10=0xe49b69c19ef14ad2UL,
  SHA512C11=0xefbe4786384f25e3UL,
  SHA512C12=0x0fc19dc68b8cd5b5UL,
  SHA512C13=0x240ca1cc77ac9c65UL,
  SHA512C14=0x2de92c6f592b0275UL,
  SHA512C15=0x4a7484aa6ea6e483UL,
  SHA512C16=0x5cb0a9dcbd41fbd4UL,
  SHA512C17=0x76f988da831153b5UL,
  SHA512C18=0x983e5152ee66dfabUL,
  SHA512C19=0xa831c66d2db43210UL,
  SHA512C1a=0xb00327c898fb213fUL,
  SHA512C1b=0xbf597fc7beef0ee4UL,
  SHA512C1c=0xc6e00bf33da88fc2UL,
  SHA512C1d=0xd5a79147930aa725UL,
  SHA512C1e=0x06ca6351e003826fUL,
  SHA512C1f=0x142929670a0e6e70UL,
  SHA512C20=0x27b70a8546d22ffcUL,
  SHA512C21=0x2e1b21385c26c926UL,
  SHA512C22=0x4d2c6dfc5ac42aedUL,
  SHA512C23=0x53380d139d95b3dfUL,
  SHA512C24=0x650a73548baf63deUL,
  SHA512C25=0x766a0abb3c77b2a8UL,
  SHA512C26=0x81c2c92e47edaee6UL,
  SHA512C27=0x92722c851482353bUL,
  SHA512C28=0xa2bfe8a14cf10364UL,
  SHA512C29=0xa81a664bbc423001UL,
  SHA512C2a=0xc24b8b70d0f89791UL,
  SHA512C2b=0xc76c51a30654be30UL,
  SHA512C2c=0xd192e819d6ef5218UL,
  SHA512C2d=0xd69906245565a910UL,
  SHA512C2e=0xf40e35855771202aUL,
  SHA512C2f=0x106aa07032bbd1b8UL,
  SHA512C30=0x19a4c116b8d2d0c8UL,
  SHA512C31=0x1e376c085141ab53UL,
  SHA512C32=0x2748774cdf8eeb99UL,
  SHA512C33=0x34b0bcb5e19b48a8UL,
  SHA512C34=0x391c0cb3c5c95a63UL,
  SHA512C35=0x4ed8aa4ae3418acbUL,
  SHA512C36=0x5b9cca4f7763e373UL,
  SHA512C37=0x682e6ff3d6b2b8a3UL,
  SHA512C38=0x748f82ee5defb2fcUL,
  SHA512C39=0x78a5636f43172f60UL,
  SHA512C3a=0x84c87814a1f0ab72UL,
  SHA512C3b=0x8cc702081a6439ecUL,
  SHA512C3c=0x90befffa23631e28UL,
  SHA512C3d=0xa4506cebde82bde9UL,
  SHA512C3e=0xbef9a3f7b2c67915UL,
  SHA512C3f=0xc67178f2e372532bUL,
  SHA512C40=0xca273eceea26619cUL,
  SHA512C41=0xd186b8c721c0c207UL,
  SHA512C42=0xeada7dd6cde0eb1eUL,
  SHA512C43=0xf57d4f7fee6ed178UL,
  SHA512C44=0x06f067aa72176fbaUL,
  SHA512C45=0x0a637dc5a2c898a6UL,
  SHA512C46=0x113f9804bef90daeUL,
  SHA512C47=0x1b710b35131c471bUL,
  SHA512C48=0x28db77f523047d84UL,
  SHA512C49=0x32caab7b40c72493UL,
  SHA512C4a=0x3c9ebe0a15c9bebcUL,
  SHA512C4b=0x431d67c49c100d4cUL,
  SHA512C4c=0x4cc5d4becb3e42b6UL,
  SHA512C4d=0x597f299cfc657e2aUL,
  SHA512C4e=0x5fcb6fab3ad6faecUL,
  SHA512C4f=0x6c44198c4a475817UL

} sha2_64_constants_t;

typedef enum ripemd160_constants
{
  RIPEMD160M_A=0x67452301U,
  RIPEMD160M_B=0xefcdab89U,
  RIPEMD160M_C=0x98badcfeU,
  RIPEMD160M_D=0x10325476U,
  RIPEMD160M_E=0xc3d2e1f0U,

  RIPEMD160C00=0x00000000U,
  RIPEMD160C10=0x5a827999U,
  RIPEMD160C20=0x6ed9eba1U,
  RIPEMD160C30=0x8f1bbcdcU,
  RIPEMD160C40=0xa953fd4eU,
  RIPEMD160C50=0x50a28be6U,
  RIPEMD160C60=0x5c4dd124U,
  RIPEMD160C70=0x6d703ef3U,
  RIPEMD160C80=0x7a6d76e9U,
  RIPEMD160C90=0x00000000U,

  RIPEMD160S00=11,
  RIPEMD160S01=14,
  RIPEMD160S02=15,
  RIPEMD160S03=12,
  RIPEMD160S04=5,
  RIPEMD160S05=8,
  RIPEMD160S06=7,
  RIPEMD160S07=9,
  RIPEMD160S08=11,
  RIPEMD160S09=13,
  RIPEMD160S0A=14,
  RIPEMD160S0B=15,
  RIPEMD160S0C=6,
  RIPEMD160S0D=7,
  RIPEMD160S0E=9,
  RIPEMD160S0F=8,

  RIPEMD160S10=7,
  RIPEMD160S11=6,
  RIPEMD160S12=8,
  RIPEMD160S13=13,
  RIPEMD160S14=11,
  RIPEMD160S15=9,
  RIPEMD160S16=7,
  RIPEMD160S17=15,
  RIPEMD160S18=7,
  RIPEMD160S19=12,
  RIPEMD160S1A=15,
  RIPEMD160S1B=9,
  RIPEMD160S1C=11,
  RIPEMD160S1D=7,
  RIPEMD160S1E=13,
  RIPEMD160S1F=12,

  RIPEMD160S20=11,
  RIPEMD160S21=13,
  RIPEMD160S22=6,
  RIPEMD160S23=7,
  RIPEMD160S24=14,
  RIPEMD160S25=9,
  RIPEMD160S26=13,
  RIPEMD160S27=15,
  RIPEMD160S28=14,
  RIPEMD160S29=8,
  RIPEMD160S2A=13,
  RIPEMD160S2B=6,
  RIPEMD160S2C=5,
  RIPEMD160S2D=12,
  RIPEMD160S2E=7,
  RIPEMD160S2F=5,

  RIPEMD160S30=11,
  RIPEMD160S31=12,
  RIPEMD160S32=14,
  RIPEMD160S33=15,
  RIPEMD160S34=14,
  RIPEMD160S35=15,
  RIPEMD160S36=9,
  RIPEMD160S37=8,
  RIPEMD160S38=9,
  RIPEMD160S39=14,
  RIPEMD160S3A=5,
  RIPEMD160S3B=6,
  RIPEMD160S3C=8,
  RIPEMD160S3D=6,
  RIPEMD160S3E=5,
  RIPEMD160S3F=12,

  RIPEMD160S40=9,
  RIPEMD160S41=15,
  RIPEMD160S42=5,
  RIPEMD160S43=11,
  RIPEMD160S44=6,
  RIPEMD160S45=8,
  RIPEMD160S46=13,
  RIPEMD160S47=12,
  RIPEMD160S48=5,
  RIPEMD160S49=12,
  RIPEMD160S4A=13,
  RIPEMD160S4B=14,
  RIPEMD160S4C=11,
  RIPEMD160S4D=8,
  RIPEMD160S4E=5,
  RIPEMD160S4F=6,

  RIPEMD160S50=8,
  RIPEMD160S51=9,
  RIPEMD160S52=9,
  RIPEMD160S53=11,
  RIPEMD160S54=13,
  RIPEMD160S55=15,
  RIPEMD160S56=15,
  RIPEMD160S57=5,
  RIPEMD160S58=7,
  RIPEMD160S59=7,
  RIPEMD160S5A=8,
  RIPEMD160S5B=11,
  RIPEMD160S5C=14,
  RIPEMD160S5D=14,
  RIPEMD160S5E=12,
  RIPEMD160S5F=6,

  RIPEMD160S60=9,
  RIPEMD160S61=13,
  RIPEMD160S62=15,
  RIPEMD160S63=7,
  RIPEMD160S64=12,
  RIPEMD160S65=8,
  RIPEMD160S66=9,
  RIPEMD160S67=11,
  RIPEMD160S68=7,
  RIPEMD160S69=7,
  RIPEMD160S6A=12,
  RIPEMD160S6B=7,
  RIPEMD160S6C=6,
  RIPEMD160S6D=15,
  RIPEMD160S6E=13,
  RIPEMD160S6F=11,

  RIPEMD160S70=9,
  RIPEMD160S71=7,
  RIPEMD160S72=15,
  RIPEMD160S73=11,
  RIPEMD160S74=8,
  RIPEMD160S75=6,
  RIPEMD160S76=6,
  RIPEMD160S77=14,
  RIPEMD160S78=12,
  RIPEMD160S79=13,
  RIPEMD160S7A=5,
  RIPEMD160S7B=14,
  RIPEMD160S7C=13,
  RIPEMD160S7D=13,
  RIPEMD160S7E=7,
  RIPEMD160S7F=5,

  RIPEMD160S80=15,
  RIPEMD160S81=5,
  RIPEMD160S82=8,
  RIPEMD160S83=11,
  RIPEMD160S84=14,
  RIPEMD160S85=14,
  RIPEMD160S86=6,
  RIPEMD160S87=14,
  RIPEMD160S88=6,
  RIPEMD160S89=9,
  RIPEMD160S8A=12,
  RIPEMD160S8B=9,
  RIPEMD160S8C=12,
  RIPEMD160S8D=5,
  RIPEMD160S8E=15,
  RIPEMD160S8F=8,

  RIPEMD160S90=8,
  RIPEMD160S91=5,
  RIPEMD160S92=12,
  RIPEMD160S93=9,
  RIPEMD160S94=12,
  RIPEMD160S95=5,
  RIPEMD160S96=14,
  RIPEMD160S97=6,
  RIPEMD160S98=8,
  RIPEMD160S99=13,
  RIPEMD160S9A=6,
  RIPEMD160S9B=5,
  RIPEMD160S9C=15,
  RIPEMD160S9D=13,
  RIPEMD160S9E=11,
  RIPEMD160S9F=11

} ripemd160_constants_t;

typedef enum keccak_constants
{
  KECCAK_RNDC_00=0x0000000000000001UL,
  KECCAK_RNDC_01=0x0000000000008082UL,
  KECCAK_RNDC_02=0x800000000000808aUL,
  KECCAK_RNDC_03=0x8000000080008000UL,
  KECCAK_RNDC_04=0x000000000000808bUL,
  KECCAK_RNDC_05=0x0000000080000001UL,
  KECCAK_RNDC_06=0x8000000080008081UL,
  KECCAK_RNDC_07=0x8000000000008009UL,
  KECCAK_RNDC_08=0x000000000000008aUL,
  KECCAK_RNDC_09=0x0000000000000088UL,
  KECCAK_RNDC_10=0x0000000080008009UL,
  KECCAK_RNDC_11=0x000000008000000aUL,
  KECCAK_RNDC_12=0x000000008000808bUL,
  KECCAK_RNDC_13=0x800000000000008bUL,
  KECCAK_RNDC_14=0x8000000000008089UL,
  KECCAK_RNDC_15=0x8000000000008003UL,
  KECCAK_RNDC_16=0x8000000000008002UL,
  KECCAK_RNDC_17=0x8000000000000080UL,
  KECCAK_RNDC_18=0x000000000000800aUL,
  KECCAK_RNDC_19=0x800000008000000aUL,
  KECCAK_RNDC_20=0x8000000080008081UL,
  KECCAK_RNDC_21=0x8000000000008080UL,
  KECCAK_RNDC_22=0x0000000080000001UL,
  KECCAK_RNDC_23=0x8000000080008008UL,

  KECCAK_PILN_00=10,
  KECCAK_PILN_01=7,
  KECCAK_PILN_02=11,
  KECCAK_PILN_03=17,
  KECCAK_PILN_04=18,
  KECCAK_PILN_05=3,
  KECCAK_PILN_06=5,
  KECCAK_PILN_07=16,
  KECCAK_PILN_08=8,
  KECCAK_PILN_09=21,
  KECCAK_PILN_10=24,
  KECCAK_PILN_11=4,
  KECCAK_PILN_12=15,
  KECCAK_PILN_13=23,
  KECCAK_PILN_14=19,
  KECCAK_PILN_15=13,
  KECCAK_PILN_16=12,
  KECCAK_PILN_17=2,
  KECCAK_PILN_18=20,
  KECCAK_PILN_19=14,
  KECCAK_PILN_20=22,
  KECCAK_PILN_21=9,
  KECCAK_PILN_22=6,
  KECCAK_PILN_23=1,

  KECCAK_ROTC_00=1,
  KECCAK_ROTC_01=3,
  KECCAK_ROTC_02=6,
  KECCAK_ROTC_03=10,
  KECCAK_ROTC_04=15,
  KECCAK_ROTC_05=21,
  KECCAK_ROTC_06=28,
  KECCAK_ROTC_07=36,
  KECCAK_ROTC_08=45,
  KECCAK_ROTC_09=55,
  KECCAK_ROTC_10=2,
  KECCAK_ROTC_11=14,
  KECCAK_ROTC_12=27,
  KECCAK_ROTC_13=41,
  KECCAK_ROTC_14=56,
  KECCAK_ROTC_15=8,
  KECCAK_ROTC_16=25,
  KECCAK_ROTC_17=43,
  KECCAK_ROTC_18=62,
  KECCAK_ROTC_19=18,
  KECCAK_ROTC_20=39,
  KECCAK_ROTC_21=61,
  KECCAK_ROTC_22=20,
  KECCAK_ROTC_23=44,

} keccak_constants_t;

typedef enum mysql323_constants
{
  MYSQL323_A=0x50305735U,
  MYSQL323_B=0x12345671U

} mysql323_constants_t;

typedef enum fortigate_constants
{
  FORTIGATE_A=0x2eba88a3U,
  FORTIGATE_B=0x4ab04c42U,
  FORTIGATE_C=0xc1307953U,
  FORTIGATE_D=0x3fcc0731U,
  FORTIGATE_E=0x299032a1U,
  FORTIGATE_F=0x705b81a9U

} fortigate_constants_t;

typedef enum blake2b_constants
{
  BLAKE2B_IV_00=0x6a09e667f3bcc908UL,
  BLAKE2B_IV_01=0xbb67ae8584caa73bUL,
  BLAKE2B_IV_02=0x3c6ef372fe94f82bUL,
  BLAKE2B_IV_03=0xa54ff53a5f1d36f1UL,
  BLAKE2B_IV_04=0x510e527fade682d1UL,
  BLAKE2B_IV_05=0x9b05688c2b3e6c1fUL,
  BLAKE2B_IV_06=0x1f83d9abfb41bd6bUL,
  BLAKE2B_IV_07=0x5be0cd19137e2179UL

} blake2b_constants_t;

typedef enum combinator_mode
{
  COMBINATOR_MODE_BASE_LEFT  = 10001,
  COMBINATOR_MODE_BASE_RIGHT = 10002

} combinator_mode_t;

#ifdef KERNEL_STATIC
typedef struct digest
{
  u32 digest_buf[DGST_ELEM];

} digest_t;
#endif

typedef struct kernel_param
{
  // We can only move attributes into this struct which do not use special declarations like __global

  u32 bitmap_mask;          // 24
  u32 bitmap_shift1;        // 25
  u32 bitmap_shift2;        // 26
  u32 salt_pos_host;        // 27
  u32 loop_pos;             // 28
  u32 loop_cnt;             // 29
  u32 il_cnt;               // 30
  u32 digests_cnt;          // 31
  u32 digests_offset_host;  // 32
  u32 combs_mode;           // 33
  u32 salt_repeat;          // 34
  u64 pws_pos;              // 35
  u64 gid_max;              // 36

} kernel_param_t;

typedef struct salt
{
  u32 salt_buf[64];
  u32 salt_buf_pc[64];

  u32 salt_len;
  u32 salt_len_pc;
  u32 salt_iter;
  u32 salt_iter2;
  u32 salt_sign[2];
  u32 salt_repeats;

  u32 orig_pos;

  u32 digests_cnt;
  u32 digests_done;

  u32 digests_offset;

  u32 scrypt_N;
  u32 scrypt_r;
  u32 scrypt_p;

} salt_t;

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
  u32  extra1;
  u32  extra2;

} plain_t;

typedef struct keyboard_layout_mapping
{
  u32 src_char;
  int src_len;
  u32 dst_char;
  int dst_len;

} keyboard_layout_mapping_t;

typedef struct hc_enc
{
  int  pos;   // source offset

  u32  cbuf;  // carry buffer
  int  clen;  // carry length

} hc_enc_t;

#endif
