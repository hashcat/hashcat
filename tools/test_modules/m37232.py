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


# the passphrase is not carried in the line, so module_verify_hash can only reproduce one that is
# a deterministic function of the word. A digest of the word is random looking lowercase hex, so
# the letters a to f do show up in the block the kernel checks

def _passphrase(word):
  return hashlib.sha256(word).hexdigest().encode()


def _pin_to_key(pin, salt, iterations):
  phase1 = hashlib.pbkdf2_hmac("sha256", pin, salt.encode(), iterations // 2, 16)
  return hashlib.pbkdf2_hmac("sha256", phase1.hex().encode(), salt.encode(), iterations // 2, 32)


def _pkcs7_pad(data):
  pad = 16 - len(data) % 16
  return data + bytes([pad]) * pad


def module_generate_hash(word, salt, iterations=None, cipher=None, iv=None):
  if cipher is None:
    cipher = CIPHERS[random_number(0, 2)]

  if cipher == 0:
    salt = ""

  if iterations is None:
    iterations = ITER_LEGACY if cipher == 0 else ITER_MODERN

  passphrase = _passphrase(word)

  key = _pin_to_key(word, salt, iterations)

  if cipher != 0 and iv is None:
    iv = random_bytes(12 if cipher == 2 else 16).hex()

  if cipher == 0:
    ct = AES.new(key, AES.MODE_ECB).encrypt(_pkcs7_pad(passphrase))
  elif cipher == 1:
    ct = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv)).encrypt(_pkcs7_pad(passphrase))
  else:
    ct = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(iv)).encrypt(passphrase)

  line = "$blockio$1*%u*%u*%s*%s*%s" % (
    cipher,
    iterations,
    salt if salt else "-",
    iv if iv else "-",
    ct[:16].hex(),
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

  if len(fields) != 6:
    return None

  version, cipher, iterations, salt, iv, ct16 = fields

  if version != "1":
    return None

  line_out = module_generate_hash(word, "" if salt == "-" else salt, int(iterations),
                                  int(cipher),
                                  None if iv == "-" else iv)

  return (line_out, word)
