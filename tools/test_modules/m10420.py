#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import ARC4

from lib import pdf
from lib.test_helpers import split_hash_word

# PDF 1.1-1.3, RC4 40 bit, collider #2: as 10400, and the 5 byte key is appended to the line.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 32], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, u=None, o=None, p=None):
  doc_id = salt
  o = o or "0" * 64
  p = -1 if p is None else int(p)

  key = pdf.compute_key(word, doc_id, o, p, 2, 0)

  rc4key = key[:5]

  u = ARC4.new(rc4key).encrypt(pdf.PADDING)

  return "$pdf$1*2*40*%d*0*16*%s*32*%s*32*%s:%s" % (p, doc_id, u.hex(), o, rc4key.hex())


def module_verify_hash(line):
  fields = line.split(b":", 1)

  if len(fields) < 2:
    return None

  # the appended key is 10 hex chars, so the password is after it

  rest = fields[1]

  idx = rest.find(b":")

  if idx != 10:
    return None

  hash_in, word = fields[0].decode(errors="replace"), rest[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 11 or data[0] != "$pdf$1":
    return None

  try:
    return (module_generate_hash(word, data[6], None, data[8], data[10], data[3]), word)
  except ValueError:
    return None
