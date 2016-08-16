#pragma once
/**
* Authors.....: Jens Steube <jens.steube@gmail.com>
*               magnum <john.magnum@hushmail.com>
*
* License.....: MIT
*/
#pragma once
#include "config.h"
#include "common.h"


#ifdef _WIN

#ifndef _BASETSD_H_
typedef UINT8  uint8_t;
//typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
typedef UINT64 uint64_t;
#endif
//typedef UINT32 uint;
#endif // _WIN

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint32_t uint; // we need to get rid of this sooner or later, for consistency
