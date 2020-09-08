#ifndef _RAR_RAWINT_
#define _RAR_RAWINT_

#define  rotls(x,n,xsize)  (((x)<<(n)) | ((x)>>(xsize-(n))))
#define  rotrs(x,n,xsize)  (((x)>>(n)) | ((x)<<(xsize-(n))))
#define  rotl32(x,n)       rotls(x,n,32)
#define  rotr32(x,n)       rotrs(x,n,32)

inline uint RawGet2(const void *Data)
{
  byte *D=(byte *)Data;
  return D[0]+(D[1]<<8);
}


inline uint32 RawGet4(const void *Data)
{
#if defined(BIG_ENDIAN) || !defined(ALLOW_MISALIGNED)
  byte *D=(byte *)Data;
  return D[0]+(D[1]<<8)+(D[2]<<16)+(D[3]<<24);
#else
  return *(uint32 *)Data;
#endif
}


inline uint64 RawGet8(const void *Data)
{
#if defined(BIG_ENDIAN) || !defined(ALLOW_MISALIGNED)
  byte *D=(byte *)Data;
  return INT32TO64(RawGet4(D+4),RawGet4(D));
#else
  return *(uint64 *)Data;
#endif
}


inline void RawPut2(uint Field,void *Data)
{
  byte *D=(byte *)Data;
  D[0]=(byte)(Field);
  D[1]=(byte)(Field>>8);
}


inline void RawPut4(uint32 Field,void *Data)
{
#if defined(BIG_ENDIAN) || !defined(ALLOW_MISALIGNED)
  byte *D=(byte *)Data;
  D[0]=(byte)(Field);
  D[1]=(byte)(Field>>8);
  D[2]=(byte)(Field>>16);
  D[3]=(byte)(Field>>24);
#else
  *(uint32 *)Data=Field;
#endif
}


inline void RawPut8(uint64 Field,void *Data)
{
#if defined(BIG_ENDIAN) || !defined(ALLOW_MISALIGNED)
  byte *D=(byte *)Data;
  D[0]=(byte)(Field);
  D[1]=(byte)(Field>>8);
  D[2]=(byte)(Field>>16);
  D[3]=(byte)(Field>>24);
  D[4]=(byte)(Field>>32);
  D[5]=(byte)(Field>>40);
  D[6]=(byte)(Field>>48);
  D[7]=(byte)(Field>>56);
#else
  *(uint64 *)Data=Field;
#endif
}


#if defined(LITTLE_ENDIAN) && defined(ALLOW_MISALIGNED)
#define USE_MEM_BYTESWAP
#endif

// Load 4 big endian bytes from memory and return uint32.
inline uint32 RawGetBE4(const byte *m)
{
#if defined(USE_MEM_BYTESWAP) && defined(_MSC_VER)
  return _byteswap_ulong(*(uint32 *)m);
#elif defined(USE_MEM_BYTESWAP) && (__GNUC__ > 3) && (__GNUC_MINOR__ > 2)
  return __builtin_bswap32(*(uint32 *)m);
#else
  return uint32(m[0]<<24) | uint32(m[1]<<16) | uint32(m[2]<<8) | m[3];
#endif
}


// Save integer to memory as big endian.
inline void RawPutBE4(uint32 i,byte *mem)
{
#if defined(USE_MEM_BYTESWAP) && defined(_MSC_VER)
  *(uint32*)mem = _byteswap_ulong(i);
#elif defined(USE_MEM_BYTESWAP) && (__GNUC__ > 3) && (__GNUC_MINOR__ > 2)
  *(uint32*)mem = __builtin_bswap32(i);
#else
  mem[0]=byte(i>>24);
  mem[1]=byte(i>>16);
  mem[2]=byte(i>>8);
  mem[3]=byte(i);
#endif
}


inline uint32 ByteSwap32(uint32 i)
{
#ifdef _MSC_VER
  return _byteswap_ulong(i);
#elif (__GNUC__ > 3) && (__GNUC_MINOR__ > 2)
  return  __builtin_bswap32(i);
#else
  return (rotl32(i,24)&0xFF00FF00)|(rotl32(i,8)&0x00FF00FF);
#endif
}

#endif
