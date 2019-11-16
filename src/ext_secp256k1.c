/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "types.h"
#include "common.h"

#include "ext_secp256k1.h"


#if !defined (WITH_LIBSECP256K1)

// some macros needed for secp256k1 header and source code includes:

// is this a good 64-bit support check ?
#if !defined(__LP64__) && !defined(_WIN64) && !defined(__x86_64__)

#define USE_SCALAR_8X32
#define USE_FIELD_10X26

#else

#define HAVE___INT128
#define USE_ASM_X86_64
// doesn't change speed much: #define USE_ECMULT_STATIC_PRECOMPUTATION

#define USE_SCALAR_4X64
#define USE_FIELD_5X52

#endif

#define USE_SCALAR_INV_BUILTIN
#define USE_FIELD_INV_BUILTIN

#define ECMULT_WINDOW_SIZE   15
#define ECMULT_GEN_PREC_BITS  4

#define USE_NUM_NONE

#include "secp256k1.c"

#endif

bool hc_secp256k1_pubkey_parse (secp256k1_pubkey *pubkey, u8 *buf, size_t length)
{
  secp256k1_context *t_ctx = secp256k1_context_create (SECP256K1_CONTEXT_NONE);

  if (secp256k1_ec_pubkey_parse (t_ctx, pubkey, buf, length) == 0)
  {
    secp256k1_context_destroy (t_ctx);

    return false;
  }

  secp256k1_context_destroy (t_ctx);

  return true;
}

bool hc_secp256k1_pubkey_tweak_mul (secp256k1_pubkey *pubkey, u8 *buf, size_t length)
{
  secp256k1_context *sctx = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);

  if (secp256k1_ec_pubkey_tweak_mul (sctx, pubkey, buf) == 0)
  {
    secp256k1_context_destroy (sctx);

    return false;
  }

  secp256k1_ec_pubkey_serialize (sctx, buf, &length, pubkey, SECP256K1_EC_COMPRESSED);

  secp256k1_context_destroy (sctx);

  return true;
}
