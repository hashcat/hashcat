#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import ARC4

from lib import pdf
from lib.test_helpers import split_hash_word

# PDF 1.1-1.3 (Acrobat 2-4), RC4 40 bit: the encryption key encrypts the padding to give U.


def module_constraints():
  return [[-1, -1], [-1, -1], [0, 32], [32, 32], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, u=None, o=None, p=None):
  doc_id = salt
  o = o or "0" * 64
  p = -1 if p is None else int(p)

  key = pdf.compute_key(word, doc_id, o, p, 2, 0)

  u = ARC4.new(key[:5]).encrypt(pdf.PADDING)

  return "$pdf$1*2*40*%d*0*16*%s*32*%s*32*%s" % (p, doc_id, u.hex(), o)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("*")

  if len(data) != 11 or data[0] != "$pdf$1" or data[1] != "2" or data[2] != "40":
    return None

  try:
    return (module_generate_hash(word, data[6], None, data[8], data[10], data[3]), word)
  except ValueError:
    return None
