#pragma once
#include "numeric_types_abbreviations.h"
/**
* digests
*/
typedef enum DGST_SIZE_ {
  DGST_SIZE_4_2 = (2 * sizeof(uint)), // 8
  DGST_SIZE_4_4 = (4 * sizeof(uint)), // 16
  DGST_SIZE_4_5 = (5 * sizeof(uint)), // 20
  DGST_SIZE_4_6 = (6 * sizeof(uint)), // 24
  DGST_SIZE_4_8 = (8 * sizeof(uint)), // 32
  DGST_SIZE_4_16 = (16 * sizeof(uint)), // 64 !!!
  DGST_SIZE_4_32 = (32 * sizeof(uint)), // 128 !!!
  DGST_SIZE_4_64 = (64 * sizeof(uint)), // 256
  DGST_SIZE_8_8 = (8 * sizeof(u64)), // 64 !!!
  DGST_SIZE_8_16 = (16 * sizeof(u64)), // 128 !!!
  DGST_SIZE_8_25 = (25 * sizeof(u64)), // 200
}DGST_SIZE;
