#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import zlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# Dashlane 4 local files. PBKDF2-HMAC-SHA1 of the password over the 32 byte salt with 10204
# iterations gives both the AES-256 key and, through EVP_BytesToKey with SHA-1 over that output and
# the first 8 bytes of the salt, the CBC IV. The first 128 bytes of the data decrypt to a 4 byte
# length, a 2 byte zlib header and raw deflate, and the password is right when inflating from byte 6
# yields the start of the XML.

ITER = 10204

MARKER = b"<?xml version"

XML = (b'<?xml version="1.0" encoding="UTF-8"?><root><item name="a">'
       b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</item></root>')

DATA_LEN = 128
SKIP     = 6

# the kernel scans the front of the inflated text for the marker, over as many bytes as this

SCAN_LEN = 64


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [64, 64],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def _bytes_to_key(pw, salt8):
  d, prev = b"", b""

  while len(d) < 48:
    prev = hashlib.sha1(prev + pw + salt8).digest()
    d += prev

  return d[:32], d[32:48]


def _inflate_partial(buf, limit=SCAN_LEN):
  # zlib keeps whatever it produced before an error, python raises, so feed it a byte at a time

  d = zlib.decompressobj(-15)

  out = b""

  try:
    for i in range(len(buf)):
      out += d.decompress(buf[i:i + 1])

      if len(out) >= limit:
        break
  except zlib.error:
    pass

  return out


def _plaintext():
  body = len(XML).to_bytes(4, "big") + zlib.compress(XML, 9)

  return body + bytes(DATA_LEN - len(body))


def module_generate_hash(word, salt, iterations=None, data=None):
  salt_bin = bytes.fromhex(salt)

  pkey = hashlib.pbkdf2_hmac("sha1", word, salt_bin, ITER, 32)

  _, iv = _bytes_to_key(pkey, salt_bin[:8])

  # only the first 128 bytes take part, and a real file carries more than that, so whatever follows
  # them is kept as it was

  tail = b""

  if data is None:
    pt = _plaintext()
  else:
    data_bin = bytes.fromhex(data)

    head = data_bin[:DATA_LEN]
    tail = data_bin[DATA_LEN:]

    pt = AES.new(pkey, AES.MODE_CBC, iv).decrypt(head)

    # a field shorter than 128 bytes decrypts to fewer than 128 plaintext bytes, and the rest of
    # what the kernel inflates is zero

    padded = pt + bytes(DATA_LEN - len(pt))

    if MARKER not in _inflate_partial(padded[SKIP:]):
      pt = random_bytes(DATA_LEN)

  ct = AES.new(pkey, AES.MODE_CBC, iv).encrypt(pt) + tail

  return "$dashlane$1*%s*%u*%s" % (salt_bin.hex(), len(ct), ct.hex())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:10] != "$dashlane$":
    return None

  fields = hash_in[10:].split("*")

  if len(fields) != 4:
    return None

  mode, salt, length, data = fields

  if mode != "1":
    return None

  if len(data) != (int(length) * 2):
    return None

  return (module_generate_hash(word, salt, None, data), word)
