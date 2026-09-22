#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import AES

from lib import gpg
from lib.test_helpers import random_bytes, random_number

# GPG symmetric secret key protection with AES-128 in OCB, which carries no trailing SHA-1: the
# kernel decides on the first decrypted block instead, which has to read "(((1:" then the name of
# the secret MPI and its length. RSA and ECC use d, DSA and ElGamal use x, and the length is two
# or three digits depending on the key type. Nothing past the marker is looked at.
#
# The s2k type octet says 1 while the key really is derived with the iterated S2K. That is what
# the mode's own parser expects, so verification derives the key the same way whatever it says.

S2K_HASH     = "sha1"
S2K_HASH_ID  = 2
S2K_TYPE     = gpg.S2K_SALTED
CIPHER_ALGO  = 7
KEY_LEN      = 16
NONCE_LEN    = 12
MODULUS_SIZE = 4096

MARKERS  = (("d", "32"), ("d", "256"), ("d", "57"), ("x", "33"))
BODY_LEN = 51


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  count    = random_number(200000000, 300000000)
  salt_raw = random_bytes(8)
  nonce    = random_bytes(NONCE_LEN)

  name, length = MARKERS[random_number(0, len(MARKERS) - 1)]

  plain = ("(((1:%s%s:" % (name, length)).encode("ascii") + random_bytes(BODY_LEN)

  key    = gpg.s2k_iterated(word, salt_raw, count, KEY_LEN, S2K_HASH)
  cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)

  data = cipher.encrypt(plain) + cipher.encrypt()

  return gpg.build(data, MODULUS_SIZE, S2K_TYPE, S2K_HASH_ID, CIPHER_ALGO, nonce, count, salt_raw)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    fields = gpg.parse(hash_in.decode("ascii"))
  except UnicodeDecodeError:
    return None

  if fields is None:
    return None

  if fields["hash_id"] != S2K_HASH_ID or fields["cipher_algo"] != CIPHER_ALGO:
    return None

  if len(fields["iv"]) != NONCE_LEN:
    return None

  key = gpg.s2k_iterated(word, fields["salt"], fields["count"], KEY_LEN, S2K_HASH)

  cipher = AES.new(key, AES.MODE_OCB, nonce=fields["iv"])

  plain = cipher.decrypt(fields["data"]) + cipher.decrypt()

  if not plain.startswith(b"(((1:"):
    return None

  cipher = AES.new(key, AES.MODE_OCB, nonce=fields["iv"])

  data = cipher.encrypt(plain) + cipher.encrypt()

  digest = gpg.build(data, fields["modulus_size"], fields["s2k_type"], S2K_HASH_ID,
                     CIPHER_ALGO, fields["iv"], fields["count"], fields["salt"])

  return (digest, word)
