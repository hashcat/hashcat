#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib.test_helpers import split_hash_word

# descrypt, DES (Unix), Traditional DES: the 2 character salt then the crypt string. crypt_r is
# libc's crypt, the same routine the perl module reached. DES keeps only 7 bits of each password
# byte, so a byte above 0x7f cracks as the byte with its top bit cleared; test.sh accepts that via
# the oracle's own verify.


def module_constraints():
  return [[0, 8], [2, 2], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return crypt_r.crypt(word.decode("latin-1"), salt)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  return (module_generate_hash(word, hash_in[:2]), word)
