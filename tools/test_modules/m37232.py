#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, random_number

# Block.io keys the backup encryption with two PBKDF2-HMAC-SHA256 phases of half the iterations
# each, where the key of phase 2 is the hex encoding of the 16 bytes phase 1 produced. The
# passphrase is encrypted with AES-256-ECB or AES-256-CBC and PKCS7 padding on legacy backups,
# and with AES-256-GCM on current ones. The passphrase is itself hex encoded, so every byte of
# the first plaintext block is one of 0-9a-f, which is what the kernel verifies against.

ITER_LEGACY = 2048
ITER_MODERN = 102400

CIPHERS = (0, 1, 2)  # 0 = AES-256-ECB, 1 = AES-256-CBC, 2 = AES-256-GCM

# fixed, so module_verify_hash can reproduce a line: the plaintext is not carried in it

PASSPHRASE = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [32, 32],
      },
      'optimized': None,
      'combined_length': None,
    },
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }


def _pin_to_key(pin, salt, iterations):
  phase1 = hashlib.pbkdf2_hmac("sha256", pin, salt.encode(), iterations // 2, 16)
  return hashlib.pbkdf2_hmac("sha256", phase1.hex().encode(), salt.encode(), iterations // 2, 32)


def _pkcs7_pad(data):
  pad = 16 - len(data) % 16
  return data + bytes([pad]) * pad


def module_generate_hash(word, salt, iterations=None, cipher=None, iv=None, pubkey=None):
  if cipher is None:
    cipher = CIPHERS[random_number(0, 2)]

  if cipher == 0:
    salt = ""

  if iterations is None:
    iterations = ITER_LEGACY if cipher == 0 else ITER_MODERN

  passphrase = PASSPHRASE.encode()

  key = _pin_to_key(word, salt, iterations)

  if cipher != 0 and iv is None:
    iv = random_bytes(12 if cipher == 2 else 16).hex()

  tag = None

  if cipher == 0:
    ct = AES.new(key, AES.MODE_ECB).encrypt(_pkcs7_pad(passphrase))
  elif cipher == 1:
    ct = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv)).encrypt(_pkcs7_pad(passphrase))
  else:
    ct, tag_bin = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(iv)).encrypt_and_digest(passphrase)
    tag = tag_bin.hex()

  if pubkey is None:
    pubkey = (b"\x03" if random_number(0, 1) else b"\x02") + random_bytes(32)

  line = "$blockio$1*%u*%u*%s*%s*%s*%s*%s" % (
    cipher,
    iterations,
    salt if salt else "-",
    iv if iv else "-",
    tag if tag else "-",
    ct[:16].hex(),
    pubkey.hex(),
  )

  return line


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[:9] != "$blockio$":
    return None

  fields = hash_in[9:].split("*")

  if len(fields) != 8:
    return None

  version, cipher, iterations, salt, iv, tag, ct16, pubkey = fields

  if version != "1":
    return None

  line_out = module_generate_hash(word, "" if salt == "-" else salt, int(iterations),
                                  int(cipher),
                                  None if iv == "-" else iv,
                                  bytes.fromhex(pubkey))

  return (line_out, word)
