#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import ARC4

from lib import pdf
from lib.test_helpers import random_number, split_hash_word

# PDF 1.4-1.6 (Acrobat 5-8), RC4 128 bit: the key encrypts md5(padding.id), then 19 more RC4 passes
# under the key XORed with the pass number.


def module_constraints():
  return [[0, 32], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, u=None, o=None, p=None, v=None, r=None, enc=None):
  doc_id = salt
  u_save = u or "0" * 64
  o = o or "0" * 64
  r = random_number(3, 4) if r is None else int(r)
  v = (2 if r == 3 else 4) if v is None else int(v)
  p = (-4 if r == 3 else -1028) if p is None else int(p)
  enc = (1 if r == 3 else random_number(0, 1)) if enc is None else int(enc)

  res = pdf.compute_key(word, doc_id, o, p, r, enc)

  digest = hashlib.md5(pdf.PADDING + bytes.fromhex(doc_id)).digest()

  u = ARC4.new(res).encrypt(digest)

  for x in range(1, 20):
    s = bytes(b ^ x for b in res[:16])
    u = ARC4.new(s).encrypt(u)

  u += bytes.fromhex(u_save)[16:32]

  return "$pdf$%d*%d*128*%d*%d*16*%s*32*%s*32*%s" % (v, r, p, enc, doc_id, u.hex(), o)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 11 or not data[0].startswith("$pdf$") or data[2] != "128":
    return None

  try:
    return (module_generate_hash(word, data[6], None, data[8], data[10], data[3], data[0][5], data[1], data[4]), word)
  except ValueError:
    return None
