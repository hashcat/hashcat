/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_BIGNUM_OPERATIONS_H
#define _INC_BIGNUM_OPERATIONS_H

DECLSPEC void mod_4096   (PRIVATE_AS u32 *n, PRIVATE_AS const u32 *m);
DECLSPEC void mul        (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y);
DECLSPEC void mul_masked (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y);
DECLSPEC void mul_mod128 (PRIVATE_AS u32 *x, PRIVATE_AS const u32 *y, PRIVATE_AS const u32 *m, PRIVATE_AS const u32 *fact);

DECLSPEC void pow_mod_precomp_g (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *b_pre, PRIVATE_AS const u32 *y, PRIVATE_AS const u32 *m, PRIVATE_AS const u32 *fact);
DECLSPEC void pow_mod           (PRIVATE_AS u32 *r, PRIVATE_AS       u32 *x,     PRIVATE_AS const u32 *y, PRIVATE_AS const u32 *m, PRIVATE_AS const u32 *fact);

DECLSPEC void simple_euclidean_gcd (PRIVATE_AS u32 *u, PRIVATE_AS u32 *v, PRIVATE_AS const u32 *m);

DECLSPEC void to_montgomery   (PRIVATE_AS u32 *r, PRIVATE_AS const u32 *a, PRIVATE_AS const u32 *m);
DECLSPEC void from_montgomery (PRIVATE_AS u32 *r, PRIVATE_AS const u32* a, PRIVATE_AS const u32 *m, PRIVATE_AS const u32 *rinv);

#endif // _INC_BIGNUM_OPERATIONS_H
