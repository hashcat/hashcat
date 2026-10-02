#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import iclass
from lib.test_helpers import random_bytes, split_hash_word

# HID iClass Legacy brute force. The password is a 5 byte index into the permuted master key: gen_key
# folds it into the low bits of the 8 key bytes, and that diversified key drives the iClass MAC over
# two card/reader nonces.


def module_constraints():
  return [[5, 5], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _gen_key(pk, index):
  key = list(pk[:8])
  carry = index

  for j in range(7, -1, -1):
    key[j] = ((pk[j] & 0x07) | ((carry & 0x1F) << 3)) & 0xFF
    carry >>= 5
    if carry == 0:
      break

  return key


def module_generate_hash(word, salt, iterations=None):
  if salt:
    parts = salt.split("$")
    pk_hex = parts[0]
    ccnr1_hex = parts[1]
    ccnr2_hex = parts[2] if len(parts) > 2 else parts[1]
  else:
    pk_hex = random_bytes(8).hex()
    ccnr1_hex = random_bytes(12).hex()
    ccnr2_hex = ccnr1_hex

  pk = list(bytes.fromhex(pk_hex))

  index = 0
  for i, pb in enumerate(word):
    index |= pb << (i * 8)

  div_key = _gen_key(pk, index)

  mac1 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr1_hex)], div_key)
  mac2 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr2_hex)], div_key)

  return "$iclass_leg$%s$%s$%08x$%s$%08x" % (pk_hex, ccnr1_hex, mac1, ccnr2_hex, mac2)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$iclass_leg$"):
    return None

  fields = hash_in[len("$iclass_leg$"):].split("$")

  if len(fields) < 5:
    return None

  pk_hex, ccnr1_hex, _mac1, ccnr2_hex, _mac2 = fields[:5]

  # A crack line carries the 8 byte diversified key as 16 hex chars (the module's
  # build_plain_postprocess prints that, not the 5 byte password), so verify straight from the key.
  # The runner's own round-trip check instead hands back the 5 byte password, which takes gen_key.
  div_key = None

  if len(word) == 16:
    try:
      raw = bytes.fromhex(word.decode("ascii"))
      if len(raw) == 8:
        div_key = list(raw)
    except (ValueError, UnicodeDecodeError):
      div_key = None

  if div_key is None:
    salt = "%s$%s$%s" % (pk_hex, ccnr1_hex, ccnr2_hex)
    return (module_generate_hash(word, salt), word)

  mac1 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr1_hex)], div_key)
  mac2 = iclass.mac([iclass.reflect8(b) for b in bytes.fromhex(ccnr2_hex)], div_key)

  return ("$iclass_leg$%s$%s$%08x$%s$%08x" % (pk_hex, ccnr1_hex, mac1, ccnr2_hex, mac2), word)
