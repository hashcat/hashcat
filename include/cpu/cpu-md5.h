#pragma once
#include <common.h>
//#include "bit_ops.h"
void md5_64 (uint block[16], uint digest[4]);
void md5_complete_no_limit(uint digest[4], uint *plain, uint plain_len);

typedef enum CPU_MD5_MAGIC_ {
  MAGIC_A = 0x67452301,
  MAGIC_B = 0xefcdab89,
  MAGIC_C = 0x98badcfe,
  MAGIC_D = 0x10325476
}CPU_MD5_MAGIC;
