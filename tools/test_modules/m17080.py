#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import gpg

# A GPG symmetrically encrypted message, the kind "gpg --symmetric" writes: iterated and salted
# S2K, AES-256 in CFB, and the SHA-1 MDC that RFC 4880 5.13 puts at the end of the plaintext,
# which is what check_decoded_data () in OpenCL/m17080-pure.cl verifies. The MDC is SHA-1
# whatever the S2K hash is.
#
# The S2K hash is what separates this mode from m17060 (SHA-1) and m17070 (SHA-256).
# S2K_HASH_ID is the OpenPGP hash algorithm id the parser requires.

S2K_HASH    = "sha512"
S2K_HASH_ID = 10


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
  return gpg.sym_mdc_generate(word, S2K_HASH, S2K_HASH_ID)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    fields = gpg.parse_sym(hash_in.decode("ascii"))
  except UnicodeDecodeError:
    return None

  if fields is None:
    return None

  digest = gpg.sym_mdc_verify(word, fields, S2K_HASH, S2K_HASH_ID)

  if digest is None:
    return None

  return (digest, word)
