#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import binascii
import hashlib
import hmac

# PostgreSQL SCRAM-SHA-256: PBKDF2-HMAC-SHA256 of the password, then the stored key
# sha256(HMAC("Client Key")) and the server key HMAC("Server Key").


def module_constraints():
  return [[0, 256], [28, 28], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  iterations = 4096 if iterations is None else int(iterations)

  salt_bytes = salt.encode("latin-1")

  key = hashlib.pbkdf2_hmac("sha256", word, salt_bytes, iterations, 32)

  server_key = hmac.new(key, b"Server Key", hashlib.sha256).digest()
  stored_key = hashlib.sha256(hmac.new(key, b"Client Key", hashlib.sha256).digest()).digest()

  return "SCRAM-SHA-256$%d:%s$%s:%s" % (iterations, base64.b64encode(salt_bytes).decode(),
                                        base64.b64encode(stored_key).decode(), base64.b64encode(server_key).decode())


def module_verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not hash_in.startswith("SCRAM-SHA-256"):
    return None

  fields = hash_in.replace("$", ":").split(":")

  if len(fields) < 3 or not fields[1].isdigit():
    return None

  try:
    salt = base64.b64decode(fields[2]).decode("latin-1")
  except binascii.Error:
    return None

  return (module_generate_hash(word, salt, fields[1]), word)
