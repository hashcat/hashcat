/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

__device__ static u32 lut3_2d (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_39 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_59 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_96 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_e4 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_e8 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

__device__ static u32 lut3_ca (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

#if __CUDA_ARCH__ >= 350

__device__ static u32 rotr32 (const u32 a, const u32 n)
{
  return __funnelshift_r (a, a, n);
}

__device__ static u32 rotl32 (const u32 a, const u32 n)
{
  return rotr32 (a, 32 - n);
}

__device__ static u64 rotr64 (const u64 a, const u32 n)
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

__device__ static u64 rotl64 (const u64 a, const u32 n)
{
  return rotr64 (a, 64 - n);
}

#else

__device__ static u32 rotr32 (const u32 a, const u32 n)
{
  return (((a) >> (n)) + ((a) << (32 - (n))));
}

__device__ static u32 rotl32 (const u32 a, const u32 n)
{
  return rotr32 (a, 32 - n);
}

__device__ static u64 rotr64 (const u64 a, const u32 n)
{
  return (((a) >> (n)) + ((a) << (64 - (n))));
}

__device__ static u64 rotl64 (const u64 a, const u32 n)
{
  return rotr64 (a, 64 - n);
}


#endif

#ifdef  VECT_SIZE1
#define VECT_SHIFT 0
#define VECT_DIV   1

typedef u8  u8x;
typedef u16 u16x;
typedef u32 u32x;
typedef u64 u64x;

__device__ static u32 l32_from_64 (u64 a)
{
  const u32 r = (u32) a;

  return r;
}

__device__ static u32 h32_from_64 (u64 a)
{
  a >>= 32;

  const u32 r = (u32) a;

  return r;
}

__device__ static u64 hl32_to_64 (const u32x a, const u32x b)
{
  u64 r;

  asm ("mov.b64 %0, {%1, %2};" : "=l"(r) : "r"(b), "r"(a));

  return r;
}

#endif

#ifdef  VECT_SIZE2
#define VECT_SHIFT 1
#define VECT_DIV   2

class u8x
{
  private:
  public:

  u8 x;
  u8 y;

    inline __device__  u8x (const u8 a, const u8 b) : x(a), y(b) { }
    inline __device__  u8x (const u8 a)             : x(a), y(a) { }

    inline __device__  u8x (void) { }
    inline __device__ ~u8x (void) { }
};

class u16x
{
  private:
  public:

  u16 x;
  u16 y;

    inline __device__  u16x (const u16 a, const u16 b) : x(a), y(b) { }
    inline __device__  u16x (const u16 a)              : x(a), y(a) { }

    inline __device__  u16x (void) { }
    inline __device__ ~u16x (void) { }
};

class u32x
{
  private:
  public:

  u32 x;
  u32 y;

    inline __device__  u32x (const u32 a, const u32 b) : x(a), y(b) { }
    inline __device__  u32x (const u32 a)              : x(a), y(a) { }

    inline __device__  u32x (void) { }
    inline __device__ ~u32x (void) { }
};

class u64x
{
  private:
  public:

  u64 x;
  u64 y;

    inline __device__  u64x (const u32x a)             : x(a.x), y(a.y) { }

    inline __device__  u64x (const u64 a, const u64 b) : x(a), y(b) { }
    inline __device__  u64x (const u64 a)              : x(a), y(a) { }

    inline __device__  u64x (void) { }
    inline __device__ ~u64x (void) { }
};

inline __device__ bool  operator != (const u32x  a, const u32  b) { return ((a.x != b  ) && (a.y != b  )); }
inline __device__ bool  operator != (const u32x  a, const u32x b) { return ((a.x != b.x) && (a.y != b.y)); }

inline __device__ void  operator ^= (u32x &a, const u32  b) { a.x ^= b;   a.y ^= b;    }
inline __device__ void  operator ^= (u32x &a, const u32x b) { a.x ^= b.x; a.y ^= b.y;  }

inline __device__ void  operator |= (u32x &a, const u32  b) { a.x |= b;   a.y |= b;    }
inline __device__ void  operator |= (u32x &a, const u32x b) { a.x |= b.x; a.y |= b.y;  }

inline __device__ void  operator &= (u32x &a, const u32  b) { a.x &= b;   a.y &= b;    }
inline __device__ void  operator &= (u32x &a, const u32x b) { a.x &= b.x; a.y &= b.y;  }

inline __device__ void  operator += (u32x &a, const u32  b) { a.x += b;   a.y += b;    }
inline __device__ void  operator += (u32x &a, const u32x b) { a.x += b.x; a.y += b.y;  }

inline __device__ void  operator -= (u32x &a, const u32  b) { a.x -= b;   a.y -= b;    }
inline __device__ void  operator -= (u32x &a, const u32x b) { a.x -= b.x; a.y -= b.y;  }

inline __device__ u32x operator << (const u32x  a, const u32  b) { return u32x ((a.x << b  ), (a.y << b  ));  }
inline __device__ u32x operator << (const u32x  a, const u32x b) { return u32x ((a.x << b.x), (a.y << b.y));  }

inline __device__ u32x operator >> (const u32x  a, const u32  b) { return u32x ((a.x >> b  ), (a.y >> b  ));  }
inline __device__ u32x operator >> (const u32x  a, const u32x b) { return u32x ((a.x >> b.x), (a.y >> b.y));  }

inline __device__ u32x operator ^  (const u32x  a, const u32  b) { return u32x ((a.x ^  b  ), (a.y ^  b  ));  }
inline __device__ u32x operator ^  (const u32x  a, const u32x b) { return u32x ((a.x ^  b.x), (a.y ^  b.y));  }

inline __device__ u32x operator |  (const u32x  a, const u32  b) { return u32x ((a.x |  b  ), (a.y |  b  ));  }
inline __device__ u32x operator |  (const u32x  a, const u32x b) { return u32x ((a.x |  b.x), (a.y |  b.y));  }

inline __device__ u32x operator &  (const u32x  a, const u32  b) { return u32x ((a.x &  b  ), (a.y &  b  ));  }
inline __device__ u32x operator &  (const u32x  a, const u32x b) { return u32x ((a.x &  b.x), (a.y &  b.y));  }

inline __device__ u32x operator +  (const u32x  a, const u32  b) { return u32x ((a.x +  b  ), (a.y +  b  ));  }
inline __device__ u32x operator +  (const u32x  a, const u32x b) { return u32x ((a.x +  b.x), (a.y +  b.y));  }

inline __device__ u32x operator -  (const u32x  a, const u32  b) { return u32x ((a.x -  b  ), (a.y -  b  ));  }
inline __device__ u32x operator -  (const u32x  a, const u32x b) { return u32x ((a.x -  b.x), (a.y -  b.y));  }

inline __device__ u32x operator *  (const u32x  a, const u32  b) { return u32x ((a.x *  b  ), (a.y *  b  ));  }
inline __device__ u32x operator *  (const u32x  a, const u32x b) { return u32x ((a.x *  b.x), (a.y *  b.y));  }

inline __device__ u32x operator ~  (const u32x  a) { return u32x (~a.x, ~a.y); }

inline __device__ bool  operator != (const u64x  a, const u64  b) { return ((a.x != b  ) && (a.y != b  )); }
inline __device__ bool  operator != (const u64x  a, const u64x b) { return ((a.x != b.x) && (a.y != b.y)); }

inline __device__ void  operator ^= (u64x &a, const u64  b) { a.x ^= b;   a.y ^= b;    }
inline __device__ void  operator ^= (u64x &a, const u64x b) { a.x ^= b.x; a.y ^= b.y;  }

inline __device__ void  operator |= (u64x &a, const u64  b) { a.x |= b;   a.y |= b;    }
inline __device__ void  operator |= (u64x &a, const u64x b) { a.x |= b.x; a.y |= b.y;  }

inline __device__ void  operator &= (u64x &a, const u64  b) { a.x &= b;   a.y &= b;    }
inline __device__ void  operator &= (u64x &a, const u64x b) { a.x &= b.x; a.y &= b.y;  }

inline __device__ void  operator += (u64x &a, const u64  b) { a.x += b;   a.y += b;    }
inline __device__ void  operator += (u64x &a, const u64x b) { a.x += b.x; a.y += b.y;  }

inline __device__ void  operator -= (u64x &a, const u64  b) { a.x -= b;   a.y -= b;    }
inline __device__ void  operator -= (u64x &a, const u64x b) { a.x -= b.x; a.y -= b.y;  }

inline __device__ u64x operator << (const u64x  a, const u64  b) { return u64x ((a.x << b  ), (a.y << b  ));  }
inline __device__ u64x operator << (const u64x  a, const u64x b) { return u64x ((a.x << b.x), (a.y << b.y));  }

inline __device__ u64x operator >> (const u64x  a, const u64  b) { return u64x ((a.x >> b  ), (a.y >> b  ));  }
inline __device__ u64x operator >> (const u64x  a, const u64x b) { return u64x ((a.x >> b.x), (a.y >> b.y));  }

inline __device__ u64x operator ^  (const u64x  a, const u64  b) { return u64x ((a.x ^  b  ), (a.y ^  b  ));  }
inline __device__ u64x operator ^  (const u64x  a, const u64x b) { return u64x ((a.x ^  b.x), (a.y ^  b.y));  }

inline __device__ u64x operator |  (const u64x  a, const u64  b) { return u64x ((a.x |  b  ), (a.y |  b  ));  }
inline __device__ u64x operator |  (const u64x  a, const u64x b) { return u64x ((a.x |  b.x), (a.y |  b.y));  }

inline __device__ u64x operator &  (const u64x  a, const u64  b) { return u64x ((a.x &  b  ), (a.y &  b  ));  }
inline __device__ u64x operator &  (const u64x  a, const u64x b) { return u64x ((a.x &  b.x), (a.y &  b.y));  }

inline __device__ u64x operator +  (const u64x  a, const u64  b) { return u64x ((a.x +  b  ), (a.y +  b  ));  }
inline __device__ u64x operator +  (const u64x  a, const u64x b) { return u64x ((a.x +  b.x), (a.y +  b.y));  }

inline __device__ u64x operator -  (const u64x  a, const u64  b) { return u64x ((a.x -  b  ), (a.y -  b  ));  }
inline __device__ u64x operator -  (const u64x  a, const u64x b) { return u64x ((a.x -  b.x), (a.y -  b.y));  }

inline __device__ u64x operator ~  (const u64x  a) { return u64x (~a.x, ~a.y); }

__device__ static u32x lut3_2d (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_2d (a.x, b.x, c.x),
               lut3_2d (a.y, b.y, c.y));
}

__device__ static u32x lut3_39 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_39 (a.x, b.x, c.x),
               lut3_39 (a.y, b.y, c.y));
}

__device__ static u32x lut3_59 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_59 (a.x, b.x, c.x),
               lut3_59 (a.y, b.y, c.y));
}

__device__ static u32x lut3_96 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_96 (a.x, b.x, c.x),
               lut3_96 (a.y, b.y, c.y));
}

__device__ static u32x lut3_e4 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_e4 (a.x, b.x, c.x),
               lut3_e4 (a.y, b.y, c.y));
}

__device__ static u32x lut3_e8 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_e8 (a.x, b.x, c.x),
               lut3_e8 (a.y, b.y, c.y));
}

__device__ static u32x lut3_ca (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_ca (a.x, b.x, c.x),
               lut3_ca (a.y, b.y, c.y));
}

__device__ static u32x rotl32(const u32x a, const u32 n)
{
  return u32x (rotl32 (a.x, n),
               rotl32 (a.y, n));
}

__device__ static u32x rotr32(const u32x a, const u32 n)
{
  return u32x (rotr32 (a.x, n),
               rotr32 (a.y, n));
}

__device__ static u64x rotl64(const u64x a, const u32 n)
{
  return u64x (rotl64 (a.x, n),
               rotl64 (a.y, n));
}

__device__ static u64x rotr64(const u64x a, const u32 n)
{
  return u64x (rotr64 (a.x, n),
               rotr64 (a.y, n));
}

__device__ static u32x __byte_perm (const u32x a, const u32x b, const u32 c)
{
  return u32x (__byte_perm (a.x, b.x, c),
               __byte_perm (a.y, b.y, c));
}

#endif

#ifdef  VECT_SIZE4
#define VECT_SHIFT 2
#define VECT_DIV   4

class u8x
{
  private:
  public:

  u8 x;
  u8 y;
  u8 z;
  u8 w;

    inline __device__  u8x (const u8 a, const u8 b, const u8 c, const u8 d) : x(a), y(b), z(c), w(d) { }
    inline __device__  u8x (const u8 a)                                     : x(a), y(a), z(a), w(a) { }

    inline __device__  u8x (void) { }
    inline __device__ ~u8x (void) { }
};

class u16x
{
  private:
  public:

  u16 x;
  u16 y;
  u16 z;
  u16 w;

    inline __device__  u16x (const u16 a, const u16 b, const u16 c, const u16 d) : x(a), y(b), z(c), w(d) { }
    inline __device__  u16x (const u16 a)                                        : x(a), y(a), z(a), w(a) { }

    inline __device__  u16x (void) { }
    inline __device__ ~u16x (void) { }
};

class u32x
{
  private:
  public:

  u32 x;
  u32 y;
  u32 z;
  u32 w;

    inline __device__  u32x (const u32 a, const u32 b, const u32 c, const u32 d) : x(a), y(b), z(c), w(d) { }
    inline __device__  u32x (const u32 a)                                        : x(a), y(a), z(a), w(a) { }

    inline __device__  u32x (void) { }
    inline __device__ ~u32x (void) { }
};

class u64x
{
  private:
  public:

  u64 x;
  u64 y;
  u64 z;
  u64 w;

    inline __device__  u64x (const u32x a)                                                  : x(a.x), y(a.y), z(a.z), w(a.w) { }

    inline __device__  u64x (const u64 a, const u64 b, const u64 c, const u64 d) : x(a), y(b), z(c), w(d) { }
    inline __device__  u64x (const u64 a)                                              : x(a), y(a), z(a), w(a) { }

    inline __device__  u64x (void) { }
    inline __device__ ~u64x (void) { }
};

inline __device__ bool  operator != (const u32x  a, const u32  b) { return ((a.x != b  ) && (a.y != b  ) && (a.z != b  ) && (a.w != b  )); }
inline __device__ bool  operator != (const u32x  a, const u32x b) { return ((a.x != b.x) && (a.y != b.y) && (a.z != b.z) && (a.w != b.w)); }

inline __device__ void  operator ^= (u32x &a, const u32  b) { a.x ^= b;   a.y ^= b;   a.z ^= b;   a.w ^= b;   }
inline __device__ void  operator ^= (u32x &a, const u32x b) { a.x ^= b.x; a.y ^= b.y; a.z ^= b.z; a.w ^= b.w; }

inline __device__ void  operator |= (u32x &a, const u32  b) { a.x |= b;   a.y |= b;   a.z |= b;   a.w |= b;   }
inline __device__ void  operator |= (u32x &a, const u32x b) { a.x |= b.x; a.y |= b.y; a.z |= b.z; a.w |= b.w; }

inline __device__ void  operator &= (u32x &a, const u32  b) { a.x &= b;   a.y &= b;   a.z &= b;   a.w &= b;   }
inline __device__ void  operator &= (u32x &a, const u32x b) { a.x &= b.x; a.y &= b.y; a.z &= b.z; a.w &= b.w; }

inline __device__ void  operator += (u32x &a, const u32  b) { a.x += b;   a.y += b;   a.z += b;   a.w += b;   }
inline __device__ void  operator += (u32x &a, const u32x b) { a.x += b.x; a.y += b.y; a.z += b.z; a.w += b.w; }

inline __device__ void  operator -= (u32x &a, const u32  b) { a.x -= b;   a.y -= b;   a.z -= b;   a.w -= b;   }
inline __device__ void  operator -= (u32x &a, const u32x b) { a.x -= b.x; a.y -= b.y; a.z -= b.z; a.w -= b.w; }

inline __device__ u32x operator << (const u32x  a, const u32  b) { return u32x ((a.x << b  ), (a.y << b  ), (a.z << b  ), (a.w << b  ));  }
inline __device__ u32x operator << (const u32x  a, const u32x b) { return u32x ((a.x << b.x), (a.y << b.y), (a.z << b.z), (a.w << b.w));  }

inline __device__ u32x operator >> (const u32x  a, const u32  b) { return u32x ((a.x >> b  ), (a.y >> b  ), (a.z >> b  ), (a.w >> b  ));  }
inline __device__ u32x operator >> (const u32x  a, const u32x b) { return u32x ((a.x >> b.x), (a.y >> b.y), (a.z >> b.z), (a.w >> b.w));  }

inline __device__ u32x operator ^  (const u32x  a, const u32  b) { return u32x ((a.x ^  b  ), (a.y ^  b  ), (a.z ^  b  ), (a.w ^  b  ));  }
inline __device__ u32x operator ^  (const u32x  a, const u32x b) { return u32x ((a.x ^  b.x), (a.y ^  b.y), (a.z ^  b.z), (a.w ^  b.w));  }

inline __device__ u32x operator |  (const u32x  a, const u32  b) { return u32x ((a.x |  b  ), (a.y |  b  ), (a.z |  b  ), (a.w |  b  ));  }
inline __device__ u32x operator |  (const u32x  a, const u32x b) { return u32x ((a.x |  b.x), (a.y |  b.y), (a.z |  b.z), (a.w |  b.w));  }

inline __device__ u32x operator &  (const u32x  a, const u32  b) { return u32x ((a.x &  b  ), (a.y &  b  ), (a.z &  b  ), (a.w &  b  ));  }
inline __device__ u32x operator &  (const u32x  a, const u32x b) { return u32x ((a.x &  b.x), (a.y &  b.y), (a.z &  b.z), (a.w &  b.w));  }

inline __device__ u32x operator +  (const u32x  a, const u32  b) { return u32x ((a.x +  b  ), (a.y +  b  ), (a.z +  b  ), (a.w +  b  ));  }
inline __device__ u32x operator +  (const u32x  a, const u32x b) { return u32x ((a.x +  b.x), (a.y +  b.y), (a.z +  b.z), (a.w +  b.w));  }

inline __device__ u32x operator -  (const u32x  a, const u32  b) { return u32x ((a.x -  b  ), (a.y -  b  ), (a.z -  b  ), (a.w -  b  ));  }
inline __device__ u32x operator -  (const u32x  a, const u32x b) { return u32x ((a.x -  b.x), (a.y -  b.y), (a.z -  b.z), (a.w -  b.w));  }

inline __device__ u32x operator *  (const u32x  a, const u32  b) { return u32x ((a.x *  b  ), (a.y *  b  ), (a.z *  b  ), (a.w *  b  ));  }
inline __device__ u32x operator *  (const u32x  a, const u32x b) { return u32x ((a.x *  b.x), (a.y *  b.y), (a.z *  b.z), (a.w *  b.w));  }

inline __device__ u32x operator ~  (const u32x  a) { return u32x (~a.x, ~a.y, ~a.z, ~a.w); }

inline __device__ bool  operator != (const u64x  a, const u64  b) { return ((a.x != b  ) && (a.y != b  ) && (a.z != b  ) && (a.w != b  )); }
inline __device__ bool  operator != (const u64x  a, const u64x b) { return ((a.x != b.x) && (a.y != b.y) && (a.z != b.z) && (a.w != b.w)); }

inline __device__ void  operator ^= (u64x &a, const u64  b) { a.x ^= b;   a.y ^= b;   a.z ^= b;   a.w ^= b;   }
inline __device__ void  operator ^= (u64x &a, const u64x b) { a.x ^= b.x; a.y ^= b.y; a.z ^= b.z; a.w ^= b.w; }

inline __device__ void  operator |= (u64x &a, const u64  b) { a.x |= b;   a.y |= b;   a.z |= b;   a.w |= b;   }
inline __device__ void  operator |= (u64x &a, const u64x b) { a.x |= b.x; a.y |= b.y; a.z |= b.z; a.w |= b.w; }

inline __device__ void  operator &= (u64x &a, const u64  b) { a.x &= b;   a.y &= b;   a.z &= b;   a.w &= b;   }
inline __device__ void  operator &= (u64x &a, const u64x b) { a.x &= b.x; a.y &= b.y; a.z &= b.z; a.w &= b.w; }

inline __device__ void  operator += (u64x &a, const u64  b) { a.x += b;   a.y += b;   a.z += b;   a.w += b;   }
inline __device__ void  operator += (u64x &a, const u64x b) { a.x += b.x; a.y += b.y; a.z += b.z; a.w += b.w; }

inline __device__ void  operator -= (u64x &a, const u64  b) { a.x -= b;   a.y -= b;   a.z -= b;   a.w -= b;   }
inline __device__ void  operator -= (u64x &a, const u64x b) { a.x -= b.x; a.y -= b.y; a.z -= b.z; a.w -= b.w; }

inline __device__ u64x operator << (const u64x  a, const u64  b) { return u64x ((a.x << b  ), (a.y << b  ), (a.z << b  ), (a.w << b  ));  }
inline __device__ u64x operator << (const u64x  a, const u64x b) { return u64x ((a.x << b.x), (a.y << b.y), (a.z << b.z), (a.w << b.w));  }

inline __device__ u64x operator >> (const u64x  a, const u64  b) { return u64x ((a.x >> b  ), (a.y >> b  ), (a.z >> b  ), (a.w >> b  ));  }
inline __device__ u64x operator >> (const u64x  a, const u64x b) { return u64x ((a.x >> b.x), (a.y >> b.y), (a.z >> b.z), (a.w >> b.w));  }

inline __device__ u64x operator ^  (const u64x  a, const u64  b) { return u64x ((a.x ^  b  ), (a.y ^  b  ), (a.z ^  b  ), (a.w ^  b  ));  }
inline __device__ u64x operator ^  (const u64x  a, const u64x b) { return u64x ((a.x ^  b.x), (a.y ^  b.y), (a.z ^  b.z), (a.w ^  b.w));  }

inline __device__ u64x operator |  (const u64x  a, const u64  b) { return u64x ((a.x |  b  ), (a.y |  b  ), (a.z |  b  ), (a.w |  b  ));  }
inline __device__ u64x operator |  (const u64x  a, const u64x b) { return u64x ((a.x |  b.x), (a.y |  b.y), (a.z |  b.z), (a.w |  b.w));  }

inline __device__ u64x operator &  (const u64x  a, const u64  b) { return u64x ((a.x &  b  ), (a.y &  b  ), (a.z &  b  ), (a.w &  b  ));  }
inline __device__ u64x operator &  (const u64x  a, const u64x b) { return u64x ((a.x &  b.x), (a.y &  b.y), (a.z &  b.z), (a.w &  b.w));  }

inline __device__ u64x operator +  (const u64x  a, const u64  b) { return u64x ((a.x +  b  ), (a.y +  b  ), (a.z +  b  ), (a.w +  b  ));  }
inline __device__ u64x operator +  (const u64x  a, const u64x b) { return u64x ((a.x +  b.x), (a.y +  b.y), (a.z +  b.z), (a.w +  b.w));  }

inline __device__ u64x operator -  (const u64x  a, const u64  b) { return u64x ((a.x -  b  ), (a.y -  b  ), (a.z -  b  ), (a.w -  b  ));  }
inline __device__ u64x operator -  (const u64x  a, const u64x b) { return u64x ((a.x -  b.x), (a.y -  b.y), (a.z -  b.z), (a.w -  b.w));  }

inline __device__ u64x operator *  (const u64x  a, const u64  b) { return u64x ((a.x *  b  ), (a.y *  b  ), (a.z *  b  ), (a.w *  b  ));  }
inline __device__ u64x operator *  (const u64x  a, const u64x b) { return u64x ((a.x *  b.x), (a.y *  b.y), (a.z *  b.z), (a.w *  b.w));  }

inline __device__ u64x operator ~  (const u64x  a) { return u64x (~a.x, ~a.y, ~a.z, ~a.w); }

__device__ static u32x lut3_2d (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_2d(a.x, b.x, c.x),
               lut3_2d (a.y, b.y, c.y),
               lut3_2d (a.z, b.z, c.z),
               lut3_2d (a.w, b.w, c.w));
}

__device__ static u32x lut3_39 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_39 (a.x, b.x, c.x),
               lut3_39 (a.y, b.y, c.y),
               lut3_39 (a.z, b.z, c.z),
               lut3_39 (a.w, b.w, c.w));
}

__device__ static u32x lut3_59 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_59 (a.x, b.x, c.x),
               lut3_59 (a.y, b.y, c.y),
               lut3_59 (a.z, b.z, c.z),
               lut3_59 (a.w, b.w, c.w));
}

__device__ static u32x lut3_96 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_96 (a.x, b.x, c.x),
               lut3_96 (a.y, b.y, c.y),
               lut3_96 (a.z, b.z, c.z),
               lut3_96 (a.w, b.w, c.w));
}

__device__ static u32x lut3_e4 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_e4 (a.x, b.x, c.x),
               lut3_e4 (a.y, b.y, c.y),
               lut3_e4 (a.z, b.z, c.z),
               lut3_e4 (a.w, b.w, c.w));
}

__device__ static u32x lut3_e8 (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_e8 (a.x, b.x, c.x),
               lut3_e8 (a.y, b.y, c.y),
               lut3_e8 (a.z, b.z, c.z),
               lut3_e8 (a.w, b.w, c.w));
}

__device__ static u32x lut3_ca (const u32x a, const u32x b, const u32x c)
{
  return u32x (lut3_ca (a.x, b.x, c.x),
               lut3_ca (a.y, b.y, c.y),
               lut3_ca (a.z, b.z, c.z),
               lut3_ca (a.w, b.w, c.w));
}

__device__ static u32x rotl32(const u32x a, const u32 n)
{
  return u32x (rotl32 (a.x, n),
               rotl32 (a.y, n),
               rotl32 (a.z, n),
               rotl32 (a.w, n));
}

__device__ static u32x rotr32(const u32x a, const u32 n)
{
  return u32x (rotr32 (a.x, n),
               rotr32 (a.y, n),
               rotr32 (a.z, n),
               rotr32 (a.w, n));
}

__device__ static u64x rotl64(const u64x a, const u32 n)
{
  return u64x (rotl64 (a.x, n),
               rotl64 (a.y, n),
               rotl64 (a.z, n),
               rotl64 (a.w, n));
}

__device__ static u64x rotr64(const u64x a, const u32 n)
{
  return u64x (rotr64 (a.x, n),
               rotr64 (a.y, n),
               rotr64 (a.z, n),
               rotr64 (a.w, n));
}

__device__ static u32x __byte_perm (const u32x a, const u32x b, const u32 c)
{
  return u32x (__byte_perm (a.x, b.x, c),
               __byte_perm (a.y, b.y, c),
               __byte_perm (a.z, b.z, c),
               __byte_perm (a.w, b.w, c));
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
  u32x digest[4];
  u32x out[4];

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
  u32x digest_buf[4];

} phpass_tmp_t;

typedef struct
{
  u32x digest_buf[4];

} md5crypt_tmp_t;

typedef struct
{
  u32x alt_result[8];

  u32x p_bytes[4];
  u32x s_bytes[4];

} sha256crypt_tmp_t;

typedef struct
{
  u64x l_alt_result[8];

  u64x l_p_bytes[2];
  u64x l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[10];
  u32x out[10];

} wpa_tmp_t;

typedef struct
{
  u64x dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[5];
  u32x out[4];

} dcc2_tmp_t;

typedef struct
{
  u32x P[18];

  u32x S0[256];
  u32x S1[256];
  u32x S2[256];
  u32x S3[256];

} bcrypt_tmp_t;

typedef struct
{
  u32x digest[2];

  u32x P[18];

  u32x S0[256];
  u32x S1[256];
  u32x S2[256];
  u32x S3[256];

} pwsafe2_tmp_t;

typedef struct
{
  u32x digest_buf[8];

} pwsafe3_tmp_t;

typedef struct
{
  u32x digest_buf[5];

} androidpin_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[10];
  u32x out[10];

} androidfde_tmp_t;

typedef struct
{
  u32x ipad[16];
  u32x opad[16];

  u32x dgst[64];
  u32x out[64];

} tc_tmp_t;

typedef struct
{
  u64x ipad[8];
  u64x opad[8];

  u64x dgst[32];
  u64x out[32];

} tc64_tmp_t;

typedef struct
{
  u32x ipad[4];
  u32x opad[4];

  u32x dgst[32];
  u32x out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[32];
  u32x out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32x ipad[8];
  u32x opad[8];

  u32x dgst[32];
  u32x out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  u64x ipad[8];
  u64x opad[8];

  u64x dgst[16];
  u64x out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  u64x out[8];

} ecryptfs_tmp_t;

typedef struct
{
  u64x ipad[8];
  u64x opad[8];

  u64x dgst[16];
  u64x out[16];

} oraclet_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[5];
  u32x out[5];

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
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[5];
  u32x out[5];

} sha1aix_tmp_t;

typedef struct
{
  u32x ipad[8];
  u32x opad[8];

  u32x dgst[8];
  u32x out[8];

} sha256aix_tmp_t;

typedef struct
{
  u64x ipad[8];
  u64x opad[8];

  u64x dgst[8];
  u64x out[8];

} sha512aix_tmp_t;

typedef struct
{
  u32x ipad[8];
  u32x opad[8];

  u32x dgst[8];
  u32x out[8];

} lastpass_tmp_t;

typedef struct
{
  u64x digest_buf[8];

} drupal7_tmp_t;

typedef struct
{
  u32x ipad[5];
  u32x opad[5];

  u32x dgst[5];
  u32x out[5];

} lotus8_tmp_t;

typedef struct
{
  u32x out[5];

} office2007_tmp_t;

typedef struct
{
  u32x out[5];

} office2010_tmp_t;

typedef struct
{
  u64x out[8];

} office2013_tmp_t;

typedef struct
{
  u32x digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  u32x block[16];

  u32x dgst[8];

  u32x block_len;
  u32x final_len;

} seven_zip_tmp_t;

typedef struct
{
  u32x Kc[16];
  u32x Kd[16];

  u32x iv[2];

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
  u32 cmds[16];

} gpu_rule_t;

/*
typedef struct
{
  u32 plain_buf[16];
  u32 plailen;

} plain_t;
*/

typedef struct
{
  u32 gidvid;
  u32 il_pos;

} plain_t;

typedef struct
{
  #ifdef _SCALAR_
  u32 i[64];
  #else
    #ifdef VECT_SIZE4
    u32x i[16];
    #endif

    #ifdef VECT_SIZE2
    u32x i[32];
    #endif

    #ifdef VECT_SIZE1
    u32x i[64];
    #endif
  #endif

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
