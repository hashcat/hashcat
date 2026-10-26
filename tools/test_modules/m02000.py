#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# STDOUT. The kernel is empty (OpenCL/m02000_mxx is a no-op), so nothing is ever hashed and nothing
# is ever cracked: the mode exists so --stdout has a kernel to borrow while it prints the candidate
# stream the host produced. There is no digest to verify a crack against, so the test is a round
# trip: the word that goes in must be the word that comes out. The driver (test.sh / test.py) runs
# the words back through 'hashcat --stdout -a 0' and compares the output to them byte for byte.
#
# module_generate_hash returns the word as hex so every byte 0x00 to 0xff survives the vector line,
# which is text; the hex is the expected output written down, and verify passes when it is the hex
# of the word.


def module_constraints():
  return [[1, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None):
  return word.hex()


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx]
  word    = line[idx + 1:]

  if word.hex().encode("ascii") != hash_in:
    return None

  return (word.hex(), word)
