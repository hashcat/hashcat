#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.test_helpers import split_hash_word

# MySQL323, the pre 4.1 password function. Spaces and tabs in the password are skipped, as MySQL
# did.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 31], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  nr, add, nr2 = 1345345333, 7, 0x12345671

  for c in word:
    if c in (0x20, 0x09):
      continue

    nr ^= ((((nr & 63) + add) * c) + (nr << 8)) & 0xffffffff
    nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xffffffff
    add = (add + c) & 0xffffffff

  return "%08x%08x" % (nr & 0x7fffffff, nr2 & 0x7fffffff)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  _, word = parts

  return (module_generate_hash(word, None), word)
