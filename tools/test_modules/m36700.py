#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# Byron era Daedalus stores a spending password check as log2(N)|r|p|salt|hash in its secret.key.
# The check is scrypt over the CBOR encoding of BLAKE2b-256 of the password, which for a 32 byte
# string is 0x58 0x20 and the bytes, compared with the stored hash.
#
# The scrypt parameters have to stay equal to the ones in the module's self-test hash: hashcat
# refuses to run when a loaded hash asks for a different scrypt configuration.

CBOR_BYTES_32 = bytes([0x58, 0x20])


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [68, 68],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def _key_material(word):
  return CBOR_BYTES_32 + hashlib.blake2b(word, digest_size=32).digest()


def module_generate_hash(word, salt, iterations=None, scrypt_n=16384, scrypt_r=8, scrypt_p=1):
  salt_bin = bytes.fromhex(salt)

  maxmem = 128 * scrypt_n * scrypt_r * (scrypt_p + 2)

  out = hashlib.scrypt(_key_material(word), salt=salt_bin, n=scrypt_n, r=scrypt_r, p=scrypt_p,
                       dklen=32, maxmem=maxmem)

  return "$cardano$2$%u$%u$%u$%s$%s" % (scrypt_n, scrypt_r, scrypt_p, salt_bin.hex(), out.hex())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:11] != "$cardano$2$":
    return None

  fields = hash_in[11:].split("$")

  if len(fields) != 5:
    return None

  scrypt_n, scrypt_r, scrypt_p, salt, stored = fields

  if len(stored) != 64:
    return None

  try:
    new_hash = module_generate_hash(word, salt, None, int(scrypt_n), int(scrypt_r), int(scrypt_p))
  except ValueError:
    return None

  return (new_hash, word)
