#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import Blowfish

from lib.test_helpers import random_number

# bcrypt (https://bcrypt.sourceforge.net/) is a Blowfish based file encryption utility writing
# .bfe files, not to be confused with the bcrypt password hash.
#
# The passphrase (8 to 56 bytes, longer ones are silently truncated to 56) runs through one
# Blowfish key schedule, then the first 8 passphrase bytes are chain-encrypted into the 56 byte
# key the data is encrypted with, and that key is appended to the plaintext before padding, so
# the last two encrypted blocks hold the key tail plus up to 7 zero bytes. The key schedule reads
# the key bytes big-endian on any machine, but the data blocks are loaded and stored in machine
# order, which the endian tag byte of the file records (0x54 little, 0x45 big).
#
# Hash format: $bfe$endian$comp$ct
#
#   endian  0 if the file was written on a little-endian machine, else 1
#   comp    compression flag byte of the file
#   ct      the last 16 bytes of the encrypted payload, hex encoded

MAX_KEY = 56


def _word_rev(b):
  # reverse each 4 byte group, to and from the little-endian machine domain

  return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def _encrypt(ctx, block, big_endian):
  if big_endian:
    return ctx.encrypt(block)

  return _word_rev(ctx.encrypt(_word_rev(block)))


def _decrypt(ctx, block, big_endian):
  if big_endian:
    return ctx.decrypt(block)

  return _word_rev(ctx.decrypt(_word_rev(block)))


def _mutate_key(word, big_endian):
  # keys.c mutateKey: one key schedule on the passphrase, then 7 chained encryptions of its
  # first 8 bytes give the 56 byte data key

  ctx = Blowfish.new(word, Blowfish.MODE_ECB)

  block = word[0:8]

  mk = b""

  for _ in range(7):
    block = _encrypt(ctx, block, big_endian)

    mk += block

  return mk


def _check(word, endian, ct):
  if len(word) < 8:
    return False

  word = word[:MAX_KEY]

  big_endian = (endian == 1)

  mk = _mutate_key(word, big_endian)

  ctx = Blowfish.new(mk, Blowfish.MODE_ECB)

  pt = _decrypt(ctx, ct, big_endian)

  for pad in range(8):
    if pt[16 - pad:] == b"\0" * pad and pt[:16 - pad] == mk[40 + pad:56]:
      return True

  return False


def _parse(hash_in):
  parts = hash_in.split("$")

  if len(parts) != 5:
    return None

  if parts[1] != "bfe":
    return None

  try:
    endian = int(parts[2])
    comp   = int(parts[3])
    ct     = bytes.fromhex(parts[4])
  except ValueError:
    return None

  if endian not in (0, 1) or comp not in (0, 1) or len(ct) != 16:
    return None

  return (endian, comp, ct)


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [8, 56],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None, iterations=None, line=None):
  if line is not None:
    parsed = _parse(line)

    if parsed is None:
      return line + "$"

    endian, comp, ct = parsed

    if _check(word, endian, ct) is True:
      return line

    # anything that is not the line itself tells the runner this password did not crack it

    return line + "$"

  endian = random_number(0, 1)
  comp   = random_number(0, 1)
  pad    = random_number(0, 7)

  # the tool accepts passphrases of 8 to 56 bytes, a shorter one cannot build a hash

  if len(word) < 8:
    return None

  mk = _mutate_key(word[:MAX_KEY], endian == 1)

  ctx = Blowfish.new(mk, Blowfish.MODE_ECB)

  # the last two plaintext blocks: the key tail from byte 40 + pad on, then pad zero bytes

  pt = mk[40 + pad:56] + b"\0" * pad

  ct = _encrypt(ctx, pt, endian == 1)

  return "$bfe$%d$%d$%s" % (endian, comp, ct.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode("latin-1"), line[idx + 1:]

  if _parse(hash_in) is None:
    return None

  new_hash = module_generate_hash(word, None, None, hash_in)

  return (new_hash, word)
