#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib
import os
import struct

# Password Safe v3. The mode is OPTS_TYPE_BINARY_HASHFILE: hashcat is handed a
# .psafe3 file rather than a hash string, and test.sh rebuilds that file by
# base64-decoding what the oracle prints, so what is printed here is the file
# itself in base64.
#
# Only the first 72 bytes of it matter to module_hash_decode:
#
#   "PWS3" || salt(32) || iterations(4, little-endian) || stretched hash(32)
#
# and the key stretch is
#
#   P = SHA256(password || salt), then SHA256 applied `iterations` more times
#   stored hash = SHA256(P)
#
# The rest of a real file is the encrypted database, which hashcat never reads,
# so a random tail stands in for it. The total length matches the module's own
# self-test file at 360 bytes.
#
# There is no pure kernel for this mode: OpenCL/ carries only m05200-pure.cl, so
# the optimized pair is [-1, -1] and a -O run reports the mode as not applicable
# rather than testing the pure kernel under an optimized label.

ITERATIONS_DEFAULT = 2048
TAIL_LEN           = 288


def module_constraints():
  return [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]]


def _psafe3(word, salt_raw, iterations, tail):
  stretched = hashlib.sha256(word + salt_raw).digest()

  for _ in range(iterations):
    stretched = hashlib.sha256(stretched).digest()

  header = b"PWS3" + salt_raw + struct.pack("<I", iterations) + hashlib.sha256(stretched).digest()

  return base64.b64encode(header + tail).decode("ascii")


def module_generate_hash(word, salt, iterations=None):
  if not iterations or iterations <= 0:
    iterations = ITERATIONS_DEFAULT

  return _psafe3(word, bytes.fromhex(salt), iterations, os.urandom(TAIL_LEN))


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    raw = base64.b64decode(hash_in)
  except Exception:
    return None

  if len(raw) < 72 or raw[:4] != b"PWS3":
    return None

  salt_raw   = raw[4:36]
  iterations = struct.unpack("<I", raw[36:40])[0]

  # the tail is whatever the artifact carried, so the hash rebuilds byte for byte

  return (_psafe3(word, salt_raw, iterations, raw[72:]), word)
