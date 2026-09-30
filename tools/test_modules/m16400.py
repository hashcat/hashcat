#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md5_state
from lib.test_helpers import split_hash_word

# CRAM-MD5 stored hash. The digest is a single MD5 compression over the password xored with 0x5c and
# padded to 64 bytes with 0x5c, with no length padding and no finalisation, so the raw state words
# are read straight back. The 32 trailing characters are kept verbatim from the stored hash.


def module_constraints():
  return [[0, 64], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, end=None):
  if end is None:
    end = "0" * 32

  block = bytes(b ^ 0x5c for b in word) + b"\x5c" * (64 - len(word))

  digest = md5_state.compress_words(block).hex()

  return "{CRAM-MD5}%s%s" % (digest, end)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if hash_in[:10] != "{CRAM-MD5}":
    return None

  end = hash_in[42:]

  return (module_generate_hash(word, end=end), word)
