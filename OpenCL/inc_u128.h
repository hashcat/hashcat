/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_U128_H
#define INC_U128_H

DECLSPEC u128_t hc_u128_make       (const u64 hi, const u64 lo);
DECLSPEC u128_t hc_u128_add_u64    (const u128_t a, const u64 b);
DECLSPEC u32    hc_u128_divmod_u32 (PRIVATE_AS u128_t *x, const u32 d);

#endif // INC_U128_H
