#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac

# CRAM-MD5: base64 of the challenge, and base64 of "user hmac-md5(challenge)".


def module_constraints():
  return [[0, 256], [0, 127], [0, 55], [0, 55], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, username=b"user"):
  challenge = salt.encode("latin-1")

  digest = hmac.new(word, challenge, hashlib.md5).hexdigest().encode()

  response = base64.b64encode(username + b" " + digest).decode()

  return "$cram_md5$%s$%s" % (base64.b64encode(challenge).decode(), response)


def module_verify_hash(line):
  if not line.startswith(b"$cram_md5$"):
    return None

  idx1 = line.find(b"$", 10)

  if idx1 < 1:
    return None

  idx2 = line.find(b":", idx1 + 1)

  if idx2 < 1:
    return None

  try:
    challenge = base64.b64decode(line[10:idx1]).decode("latin-1")
    response = base64.b64decode(line[idx1 + 1:idx2])
  except binascii.Error:
    return None

  word = line[idx2 + 1:]

  return (module_generate_hash(word, challenge, None, response[:len(response) - 32 - 1]), word)
