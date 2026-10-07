#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import crypt_r

from lib.test_helpers import split_hash_word

# descrypt, DES (Unix), Traditional DES: the 2 character salt then the crypt string. crypt_r is
# libc's crypt, the same routine the perl module reached. DES keeps only 7 bits of each password
# byte, so hashcat prints a cracked byte above 0x7f with its top bit cleared wherever that is
# printable, and the oracle's own verify accepts it.


def module_constraints():
  return [[0, 8], [2, 2], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return crypt_r.crypt(word.decode("utf-8"), salt)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  text = utf8_spelling(word)

  if text is None:
    return None

  return (crypt_r.crypt(text, hash_in[:2]), word)


def utf8_spelling(word):
  # A printed password with some top bits cleared need not be UTF-8, and crypt_r takes only a str.
  # Every setting of the top bits hashes the same, and the generated password is one of them, so
  # the first setting that decodes stands in for the word. A byte whose low 7 bits are 0 keeps its
  # top bit, because a NUL would end the key early.

  n = len(word)

  for top in range(1 << n):
    spelling = bytearray(n)

    for i in range(n):
      low = word[i] & 0x7f

      spelling[i] = (low | 0x80) if ((((top >> i) & 1) == 1) or (low == 0)) else low

    try:
      text = spelling.decode("utf-8")
    except UnicodeDecodeError:
      continue

    return text

  return None
