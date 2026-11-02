#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import md6
from lib.test_helpers import split_hash_word

# MD6-256, see lib/md6.py. The pure kernels run the stored recipe md6256(pass), the optimized ones
# hash a single block and so take up to 55 bytes.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  return md6.md6256(word).hex()


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
