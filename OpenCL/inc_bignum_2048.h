/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BIGNUM_2048_H
#define INC_BIGNUM_2048_H

DECLSPEC void bn2048_copy     (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a);
DECLSPEC u32  bn2048_ge       (PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b);
DECLSPEC void bn2048_sub      (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b);
DECLSPEC void bn2048_mod_dbl  (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *n);
DECLSPEC void bn2048_mont_mul (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *b, PRIVATE_AS const u32 *n, const u32 n0);

DECLSPEC bool bn2048_mont_ctx_init (PRIVATE_AS const u32 *n, PRIVATE_AS u32 *n0, PRIVATE_AS u32 *mont_one);
DECLSPEC void bn2048_to_mont       (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *n, const u32 n0, PRIVATE_AS const u32 *mont_one);
DECLSPEC void bn2048_from_mont     (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *n, const u32 n0);
DECLSPEC void bn2048_powm          (PRIVATE_AS u32 *out, PRIVATE_AS const u32 *in, PRIVATE_AS const u32 *d, PRIVATE_AS const u32 *n, const u32 n0, PRIVATE_AS const u32 *mont_one);

DECLSPEC void bn2048_from_be (PRIVATE_AS u32 *limbs, PRIVATE_AS const u32 *be);
DECLSPEC void bn2048_to_be   (PRIVATE_AS u32 *be,    PRIVATE_AS const u32 *limbs);

#endif // INC_BIGNUM_2048_H
