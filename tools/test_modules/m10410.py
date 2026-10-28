#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import ARC4

from lib import pdf

# PDF 1.1-1.3, RC4 40 bit, collider #1: the candidate is the 5 byte RC4 key.


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': None,
      'optimized': {
        'password_length': [5, 5],
        'salt_length': [32, 32],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None, o=None, p=None):
  doc_id = salt
  o = o or "0" * 64
  p = -1 if p is None else int(p)

  u = ARC4.new(word).encrypt(pdf.PADDING)

  return "$pdf$1*2*40*%d*0*16*%s*32*%s*32*%s" % (p, doc_id, u.hex(), o)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 11 or data[0] != "$pdf$1" or len(word) != 5:
    return None

  return (module_generate_hash(word, data[6], None, data[10], data[3]), word)
