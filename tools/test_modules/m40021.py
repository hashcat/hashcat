#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

# Cisco-IOS $8$: PBKDF2-HMAC-SHA256, base64 encoded, then moved into Cisco's own alphabet.

CISCO = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def module_constraints():
  return [[0, 256], [14, 14], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 20000 if iterations is None else int(iterations)

  raw = hashlib.pbkdf2_hmac("sha256", word, salt.encode(), iterations)

  return "$8$%s$%s" % (salt, base64.b64encode(raw).decode()[:43].translate(CISCO))


def module_verify_hash(line):
  if not line.startswith(b"$8$") or line.find(b"$", 3) != 17:
    return None

  idx = line.find(b":", 18)

  if idx < 1:
    return None

  return (module_generate_hash(line[idx + 1:], line[3:17].decode()), line[idx + 1:])
