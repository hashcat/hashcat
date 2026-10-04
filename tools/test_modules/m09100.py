#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import lotus

# Lotus Notes/Domino 8.5.x (SEC_pwddigest_V3). The password runs through the Domino "big md" mix
# twice to build the -m 8700 style tmp hash, which PBKDF2-HMAC-SHA1 then salts. The account file
# stores salt, iteration count, a two char field and the 8 byte digest in a wider Domino base64.


def _b85x_encode(final):
  b = bytearray(final)

  b[3] = (b[3] + 4) & 0xff

  out = ""

  for i in range(0, 36, 3):
    out += lotus.base64_encode((b[i] << 16) | (b[i + 1] << 8) | b[i + 2], 4)

  return out


def _b85x_decode(s):
  raw = bytearray()

  for i in range(0, len(s), 4):
    num = lotus.base64_decode(s[i:i + 4], 4)

    raw += bytes(((num >> 16) & 0xff, (num >> 8) & 0xff, num & 0xff))

  salt = bytearray(raw[0:16])
  salt[3] = (salt[3] - 4) & 0xff

  iterations = raw[16:26]
  chars      = raw[26:28]

  return bytes(salt), iterations, chars


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, param=None):
  if iterations is None:
    iterations = 5000

  chars = "02" if param is None else param

  state = lotus.big_md(list(word), len(word))

  salt_part = salt[0:5]

  digest_str = "(" + bytes(state).hex() + ")"

  state = lotus.big_md(list((salt_part + digest_str.upper()).encode("latin-1")), 34)

  hash_buf = bytes(state)

  tmp_hash = "(G%s)" % lotus.encode(salt_part.encode("latin-1") + hash_buf, None)

  digest_new = hashlib.pbkdf2_hmac("sha1", tmp_hash.encode("latin-1"), salt.encode("latin-1"),
                                   int(iterations), 8)

  iter_str = "%010d" % int(iterations)

  final = salt.encode("latin-1") + iter_str.encode("latin-1") + chars.encode("latin-1") + digest_new

  return "(H%s)" % _b85x_encode(final)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode("latin-1")
  word    = line[idx + 1:]

  base64_part = hash_in[2:-1]

  if len(base64_part) != 48:
    return None

  salt, iterations, chars = _b85x_decode(base64_part)

  try:
    iter_int = int(iterations.decode("latin-1"))
  except ValueError:
    return None

  if iter_int < 1:
    return None

  new_hash = module_generate_hash(word, salt.decode("latin-1"), iter_int, chars.decode("latin-1"))

  return (new_hash, word)
