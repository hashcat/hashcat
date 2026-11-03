#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a Byron era Cardano Daedalus wallet for hash-mode 36700.
#
# A Byron era secret.key stores, beside each encrypted key, a spending password check as the string
# log2(N)|r|p|salt|hash, where the salt and the hash are base64. The check is scrypt over the CBOR
# encoding of BLAKE2b-256 of the password, compared with the stored hash, and that is what
# hash-mode 36700 cracks.
#
# The file itself is CBOR, but the string above is plain ASCII inside it, so it is read out by
# pattern rather than by decoding the whole structure. That keeps this free of a CBOR dependency
# and works on a wallet backup as well as on secret.key.
#
# A Shelley era wallet does not store this string and is not covered.

import argparse
import base64
import binascii
import re
import sys

# log2(N) | r | p | salt | hash, the two trailing fields base64

PASSPHRASE_HASH = re.compile(rb"([0-9]{1,2})\|([0-9]{1,3})\|([0-9]{1,3})\|([A-Za-z0-9+/]+={0,2})\|([A-Za-z0-9+/]+={0,2})")

# scrypt writes 32 bytes here, and the salt is longer than its 32 bytes because cardano-sl stored
# it CBOR wrapped

HASH_LEN = 32

SALT_LEN_MIN = 8
SALT_LEN_MAX = 64


def hash_lines(data: bytes) -> list:
  lines = []

  for match in PASSPHRASE_HASH.finditer(data):
    log_n, r, p, salt_b64, hash_b64 = match.groups()

    try:
      salt = base64.b64decode(salt_b64, validate=True)
      stored = base64.b64decode(hash_b64, validate=True)
    except binascii.Error:
      continue

    if len(stored) != HASH_LEN: continue
    if len(salt) < SALT_LEN_MIN: continue
    if len(salt) > SALT_LEN_MAX: continue

    scrypt_n = 1 << int(log_n)

    line = "$cardano$2$%u$%u$%u$%s$%s" % (scrypt_n, int(r), int(p), salt.hex(), stored.hex())

    if line in lines: continue

    lines.append(line)

  return lines


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a Byron era Daedalus wallet for hash-mode 36700.")

  parser.add_argument("path", nargs="+", help="a Daedalus secret.key, or a wallet backup holding one")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(path, "rb") as fd:
        lines = hash_lines(fd.read())
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (path, e.strerror))

      rc = 1

      continue

    if len(lines) == 0:
      sys.stderr.write("%s: no spending password check found, a Byron era wallet is needed\n" % path)

      rc = 1

      continue

    for line in lines: print(line)

  return rc


if __name__ == "__main__":
  sys.exit(main())
