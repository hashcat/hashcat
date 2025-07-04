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

#ifndef ARGON2_KAT_H
#define ARGON2_KAT_H

#include "core.h"

/*
 * Initial KAT function that prints the inputs to the file
 * @param  blockhash  Array that contains pre-hashing digest
 * @param  context Holds inputs
 * @param  type Argon2 type
 * @pre blockhash must point to INPUT_INITIAL_HASH_LENGTH bytes
 * @pre context member pointers must point to allocated memory of size according
 * to the length values
 */
void initial_kat(const uint8_t *blockhash, const argon2_context *context,
                 argon2_type type);

/*
 * Function that prints the output tag
 * @param  out  output array pointer
 * @param  outlen digest length
 * @pre out must point to @a outlen bytes
 **/
void print_tag(const void *out, uint32_t outlen);

/*
 * Function that prints the internal state at given moment
 * @param  instance pointer to the current instance
 * @param  pass current pass number
 * @pre instance must have necessary memory allocated
 **/
void internal_kat(const argon2_instance_t *instance, uint32_t pass);

#endif
