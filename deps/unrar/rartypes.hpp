#ifndef _RAR_TYPES_
#define _RAR_TYPES_

#include <stdint.h>

typedef uint8_t          byte;   // Unsigned 8 bits.
typedef uint16_t         ushort; // Preferably 16 bits, but can be more.
typedef unsigned int     uint;   // 32 bits or more.
typedef uint32_t         uint32; // 32 bits exactly.
typedef int32_t          int32;  // Signed 32 bits exactly.
typedef uint64_t         uint64; // 64 bits exactly.
typedef int64_t          int64;  // Signed 64 bits exactly.
typedef wchar_t          wchar;  // Unicode character

// Get lowest 16 bits.
#define GET_SHORT16(x) (sizeof(ushort)==2 ? (ushort)(x):((x)&0xffff))

// Make 64 bit integer from two 32 bit.
#define INT32TO64(high,low) ((((uint64)(high))<<32)+((uint64)low))

// Maximum int64 value.
#define MAX_INT64 int64(INT32TO64(0x7fffffff,0xffffffff))

// Special int64 value, large enough to never be found in real life
// and small enough to fit to both signed and unsigned 64-bit ints.
// We use it in situations, when we need to indicate that parameter 
// is not defined and probably should be calculated inside of function.
// Lower part is intentionally 0x7fffffff, not 0xffffffff, to make it 
// compatible with 32 bit int64 if 64 bit type is not supported.
#define INT64NDF INT32TO64(0x7fffffff,0x7fffffff)

#endif
