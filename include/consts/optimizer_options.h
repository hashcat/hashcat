#pragma once
/**
* optimizer options
*/
typedef enum OPTI_TYPE_ {
  OPTI_TYPE_INVALID = 0,
  OPTI_TYPE_ZERO_BYTE = (1 << 1),
  OPTI_TYPE_PRECOMPUTE_INIT = (1 << 2),
  OPTI_TYPE_PRECOMPUTE_MERKLE = (1 << 3),
  OPTI_TYPE_PRECOMPUTE_PERMUT = (1 << 4),
  OPTI_TYPE_MEET_IN_MIDDLE = (1 << 5),
  OPTI_TYPE_EARLY_SKIP = (1 << 6),
  OPTI_TYPE_NOT_SALTED = (1 << 7),
  OPTI_TYPE_NOT_ITERATED = (1 << 8),
  OPTI_TYPE_PREPENDED_SALT = (1 << 9),
  OPTI_TYPE_APPENDED_SALT = (1 << 10),
  OPTI_TYPE_SINGLE_HASH = (1 << 11),
  OPTI_TYPE_SINGLE_SALT = (1 << 12),
  OPTI_TYPE_BRUTE_FORCE = (1 << 13),
  OPTI_TYPE_RAW_HASH = (1 << 14),
  OPTI_TYPE_SLOW_HASH_SIMD = (1 << 15),
  OPTI_TYPE_USES_BITS_8 = (1 << 16),
  OPTI_TYPE_USES_BITS_16 = (1 << 17),
  OPTI_TYPE_USES_BITS_32 = (1 << 18),
  OPTI_TYPE_USES_BITS_64 = (1 << 19)
} OPTI_TYPE;

static const char OPTI_STR_ZERO_BYTE[] = "Zero-Byte";
static const char OPTI_STR_PRECOMPUTE_INIT[] = "Precompute-Init";
static const char OPTI_STR_PRECOMPUTE_MERKLE[] = "Precompute-Merkle-Demgard";
static const char OPTI_STR_PRECOMPUTE_PERMUT[] = "Precompute-Final-Permutation";
static const char OPTI_STR_MEET_IN_MIDDLE[] = "Meet-In-The-Middle";
static const char OPTI_STR_EARLY_SKIP[] = "Early-Skip";
static const char OPTI_STR_NOT_SALTED[] = "Not-Salted";
static const char OPTI_STR_NOT_ITERATED[] = "Not-Iterated";
static const char OPTI_STR_PREPENDED_SALT[] = "Prepended-Salt";
static const char OPTI_STR_APPENDED_SALT[] = "Appended-Salt";
static const char OPTI_STR_SINGLE_HASH[] = "Single-Hash";
static const char OPTI_STR_SINGLE_SALT[] = "Single-Salt";
static const char OPTI_STR_BRUTE_FORCE[] = "Brute-Force";
static const char OPTI_STR_RAW_HASH[] = "Raw-Hash";
static const char OPTI_STR_SLOW_HASH_SIMD[] = "Slow-Hash-SIMD";
static const char OPTI_STR_USES_BITS_8[] = "Uses-8-Bit";
static const char OPTI_STR_USES_BITS_16[] = "Uses-16-Bit";
static const char OPTI_STR_USES_BITS_32[] = "Uses-32-Bit";
static const char OPTI_STR_USES_BITS_64[] = "Uses-64-Bit";
