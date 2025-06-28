/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef ENCODING_H
#define ENCODING_H
#include "argon2.h"

#define ARGON2_MAX_DECODED_LANES UINT32_C(255)
#define ARGON2_MIN_DECODED_SALT_LEN UINT32_C(8)
#define ARGON2_MIN_DECODED_OUT_LEN UINT32_C(12)

/*
* encode an Argon2 hash string into the provided buffer. 'dst_len'
* contains the size, in characters, of the 'dst' buffer; if 'dst_len'
* is less than the number of required characters (including the
* terminating 0), then this function returns ARGON2_ENCODING_ERROR.
*
* on success, ARGON2_OK is returned.
*/
int encode_string(char *dst, size_t dst_len, argon2_context *ctx,
                  argon2_type type);

/*
* Decodes an Argon2 hash string into the provided structure 'ctx'.
* The only fields that must be set prior to this call are ctx.saltlen and
* ctx.outlen (which must be the maximal salt and out length values that are
* allowed), ctx.salt and ctx.out (which must be buffers of the specified
* length), and ctx.pwd and ctx.pwdlen which must hold a valid password.
*
* Invalid input string causes an error. On success, the ctx is valid and all
* fields have been initialized.
*
* Returned value is ARGON2_OK on success, other ARGON2_ codes on error.
*/
int decode_string(argon2_context *ctx, const char *str, argon2_type type);

/* Returns the length of the encoded byte stream with length len */
size_t b64len(uint32_t len);

/* Returns the length of the encoded number num */
size_t numlen(uint32_t num);

#endif
