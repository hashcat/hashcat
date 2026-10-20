#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# Mode 4000 needs --hash-recipe, which test.py supplies on every run. This recipe combines one
# little endian family with two big endian families. It tests uppercase hex chaining with ^2,
# raw output, hex slices starting at zero and at an offset, both string quote styles, and
# transformed copies of the password and salt. The input always exceeds one block, covering
# most of the kernel's input assembly paths in one recipe.

HASHCAT_ARGS = ["--hash-recipe", r'''sha256(md5_uc^2(upper(salt)) . ':' . pass . sha1_bin(pass) . trunc(upper(md5(pass)), 20) . cut(sha1(salt), 8, 12) . "\x01" . cap(rev(pass)))''']


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def md5_uc_rounds(data, rounds):
  for _ in range(rounds):
    data = hashlib.md5(data).hexdigest().upper().encode()

  return data


# Convert the first lowercase ASCII letter to uppercase, following hx's cap () behavior.

def cap(data):
  out = bytearray(data)

  for i in range(len(out)):
    if (out[i] >= 0x61) and (out[i] <= 0x7a):
      out[i] -= 32

      break

  return bytes(out)


def module_generate_hash(word, salt, iterations=None):
  salt_bytes = salt.encode()

  data  = md5_uc_rounds(salt_bytes.upper(), 2)
  data += b":"
  data += word
  data += hashlib.sha1(word).digest()
  data += hashlib.md5(word).hexdigest().upper().encode()[:20]
  data += hashlib.sha1(salt_bytes).hexdigest().encode()[8:20]
  data += b"\x01"
  data += cap(word[::-1])

  digest = hashlib.sha256(data).hexdigest()

  return "%s*%s" % (digest, salt)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("*", 1)

  if len(fields) < 2:
    return None

  return (module_generate_hash(word, fields[1]), word)
