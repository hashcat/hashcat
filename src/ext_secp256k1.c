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
#if !defined (__LP64__) && !defined (_WIN64) && !defined (__x86_64__)

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
  #if !defined (WITH_LIBSECP256K1)

  secp256k1_context *sctx = secp256k1_context_create (SECP256K1_CONTEXT_NONE);

  secp256k1_gej res;
  secp256k1_ge  pt;

  // load the public key and 32 byte scalar:

  secp256k1_pubkey_load (sctx, &pt, pubkey);

  int overflow = 0;

  secp256k1_scalar s;

  secp256k1_scalar_set_b32 (&s, buf, &overflow);

  if (overflow != 0)
  {
    secp256k1_scalar_clear (&s);

    secp256k1_context_destroy (sctx);

    return false;
  }

  if (secp256k1_scalar_is_zero (&s))
  {
    secp256k1_scalar_clear (&s);

    secp256k1_context_destroy (sctx);

    return false;
  }


  // main multiply operation:

  const size_t scalar_size = (length - 1) * 8;

  secp256k1_ecmult_const (&res, &pt, &s, scalar_size);
  secp256k1_ge_set_gej   (&pt, &res);
  secp256k1_fe_normalize (&pt.x);
  secp256k1_fe_normalize (&pt.y);


  // output:

  buf[0] = 0x02 | secp256k1_fe_is_odd (&pt.y);

  secp256k1_fe_get_b32 (buf + 1, &pt.x);


  // cleanup:

  secp256k1_scalar_clear (&s);

  secp256k1_context_destroy (sctx);

  #else

  // ATTENTION: this way to multiply was much slower in our tests

  secp256k1_context *sctx = secp256k1_context_create (SECP256K1_CONTEXT_VERIFY);


  // main multiply operation:

  if (secp256k1_ec_pubkey_tweak_mul (sctx, pubkey, buf) == 0)
  {
    secp256k1_context_destroy (sctx);

    return false;
  }


  // output:

  secp256k1_ec_pubkey_serialize (sctx, buf, &length, pubkey, SECP256K1_EC_COMPRESSED);


  // cleanup:

  secp256k1_context_destroy (sctx);

  #endif

  return true;
}
