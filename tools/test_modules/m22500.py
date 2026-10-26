#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number

# MultiBit Classic / KnCGroup / bitcoinj wallet key blocks: AES-256-CBC of 32 bytes, with the key
# and IV coming from three chained MD5s of password.salt. A recovered block decrypts to a plaintext
# that starts with one of a few known markers, which is the verification step.

BASE58_CHARS   = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BITCOINJ_CHARS = ".abcdefghijklmnopqrstuvwxyz"


def module_constraints():
  return [[0, 256], [8, 8], [0, 31], [8, 8], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, data=None):
  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  word_salt = word + salt_bytes

  key1 = hashlib.md5(word_salt).digest()
  key2 = hashlib.md5(key1 + word_salt).digest()
  iv   = hashlib.md5(key2 + word_salt).digest()

  aes = AES.new(key1 + key2, AES.MODE_CBC, iv)

  if data is None:
    # type 0: MultiBit Classic MD5, 1: KnCGroup, 2: bitcoinj
    dtype = random_number(0, 2)

    if dtype == 0:
      chars_at_start = ["K", "L", "Q", "5"]

      plain = chars_at_start[random_number(0, len(chars_at_start) - 1)]

      for _ in range(1, 32):
        plain += BASE58_CHARS[random_number(0, len(BASE58_CHARS) - 1)]
    elif dtype == 1:
      plain = "\n"
      plain += chr(random_number(0, 127))
      plain += "org."

      for _ in range(6, 32):
        plain += BITCOINJ_CHARS[random_number(0, len(BITCOINJ_CHARS) - 1)]
    else:
      plain = "# KEEP YOUR PRIVATE KEYS SAFE! A"

    key = aes.encrypt(plain.encode("latin-1"))
  else:
    plain = aes.decrypt(data)

    key = plain

    char_at_start = plain[0:1]

    if char_at_start in (b"K", b"L", b"Q", b"5"):
      error = 0

      for i in range(1, 32):
        if BASE58_CHARS.find(chr(plain[i])) < 0:
          error = 1
          break

      if error == 0:
        key = data
    elif char_at_start == b"\n":
      if plain[1] < 128:
        if plain[2:6] == b"org.":
          error = 0

          for i in range(6, 14):
            if BITCOINJ_CHARS.find(chr(plain[i])) < 0:
              error = 1
              break

          if error == 0:
            key = data
    elif char_at_start == b"#":
      if plain[0:16] == b"# KEEP YOUR PRIV":
        key = data

  return "$multibit$1*%s*%s" % (salt_bytes.hex(), key.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[0:12] != "$multibit$1*":
    return None

  if hash_in.find("*", 12) != 28:
    return None

  salt_hex = hash_in[12:28]
  data_hex = hash_in[29:]

  if len(salt_hex) != 16 or len(data_hex) != 64:
    return None

  try:
    salt = bytes.fromhex(salt_hex)
    data = bytes.fromhex(data_hex)
  except ValueError:
    return None

  return (module_generate_hash(word, salt, None, data), word)
