#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a sollet.io wallet for hash-mode 44200.
#
# sollet keeps its mnemonic under the localStorage key "locked", as the JSON object
# {"encrypted":...,"nonce":...,"kdf":"pbkdf2","salt":...,"iterations":...,"digest":"sha256"} with
# the binary fields in base58. The input is that object, the object as a string, anything holding
# one of those, or a file that is not JSON at all but contains the object as plain text. Every
# object found is written out, one line each.
# Only the iteration count, the salt, the nonce and the first 16 bytes of the ciphertext are
# written, so the line carries nothing of the mnemonic.

import argparse
import json
import sys

REQUIRED = ("encrypted", "nonce", "salt")

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

SALT_LEN  = 16
NONCE_LEN = 24
TAG_LEN   = 16

# the head of the ciphertext the mode checks its known plaintext against

CT_LEN = 16


def b58decode(text: str) -> bytes:
  n = 0

  for c in text:
    idx = B58.find(c)

    if idx < 0: raise ValueError("%r is not base58" % c)

    n = n * 58 + idx

  raw = n.to_bytes((n.bit_length() + 7) // 8, "big")

  pad = len(text) - len(text.lstrip("1"))

  return bytes(pad) + raw


def b58_field(obj: dict, name: str, want_len: int) -> bytes:
  value = obj[name]

  if isinstance(value, str) == False: raise ValueError("%s is not a string" % name)

  raw = b58decode(value)

  if want_len > 0:
    if len(raw) != want_len: raise ValueError("%s is %u bytes, expected %u" % (name, len(raw), want_len))

  return raw


def objects(obj) -> list:
  if isinstance(obj, str) == True:
    try:
      return objects(json.loads(obj))
    except json.JSONDecodeError:
      return []

  if isinstance(obj, dict) == True:
    found = []

    for name in REQUIRED:
      if name not in obj: break
    else:
      found.append(obj)

    for value in obj.values(): found += objects(value)

    return found

  if isinstance(obj, list) == True:
    found = []

    for value in obj: found += objects(value)

    return found

  return []


def scan(text: str) -> list:
  # a file that is not JSON may still hold the object as text, plain or as an escaped JSON string

  decoder = json.JSONDecoder()

  found = []

  for start_tag, unescape in (('{"encrypted"', False), ('{\\"encrypted\\"', True)):
    pos = text.find(start_tag)

    while pos >= 0:
      chunk = text[pos:]

      if unescape == True:
        end = chunk.find("}")

        chunk = chunk[:end + 1].replace('\\"', '"') if end >= 0 else ""

      try:
        obj, _ = decoder.raw_decode(chunk)

        found += objects(obj)
      except json.JSONDecodeError:
        pass

      pos = text.find(start_tag, pos + 1)

  return found


def hash_line(obj: dict) -> str:
  kdf = obj.get("kdf", "pbkdf2")

  if kdf != "pbkdf2": raise ValueError("the %s kdf is not supported, only pbkdf2 is" % kdf)

  digest = obj.get("digest", "sha256")

  if digest != "sha256": raise ValueError("the %s digest is not supported, only sha256 is" % digest)

  iterations = obj.get("iterations", 100000)

  if isinstance(iterations, int) == False: raise ValueError("the iteration count %r is not a number" % iterations)

  if iterations < 1: raise ValueError("an iteration count of %u is not usable" % iterations)

  salt      = b58_field(obj, "salt",      SALT_LEN)
  nonce     = b58_field(obj, "nonce",     NONCE_LEN)
  encrypted = b58_field(obj, "encrypted", 0)

  if len(encrypted) < (TAG_LEN + CT_LEN): raise ValueError("the box is %u bytes, at least %u are needed" % (len(encrypted), TAG_LEN + CT_LEN))

  ct = encrypted[TAG_LEN:TAG_LEN + CT_LEN]

  line = "$sollet$%u*%s*%s*%s" % (iterations, salt.hex(), nonce.hex(), ct.hex())

  return line


def main() -> int:
  parser = argparse.ArgumentParser(description="Write the hash line of a sollet.io wallet for hash-mode 44200.")

  parser.add_argument("path", nargs="+", help="a file holding the \"locked\" entry of the wallet, as JSON or as text")

  args = parser.parse_args()

  rc = 0

  for path in args.path:
    try:
      with open(path, "rb") as fd:
        data = fd.read()
    except OSError as e:
      sys.stderr.write("%s: %s\n" % (path, e.strerror))

      rc = 1

      continue

    text = data.decode("latin-1")

    try:
      found = objects(json.loads(text))
    except json.JSONDecodeError:
      found = scan(text)

    if len(found) == 0:
      sys.stderr.write("%s: no sollet \"locked\" entry found\n" % path)

      rc = 1

      continue

    seen = []

    for obj in found:
      try:
        line = hash_line(obj)
      except ValueError as e:
        sys.stderr.write("%s: %s\n" % (path, e))

        rc = 1

        continue

      if line in seen: continue

      seen.append(line)

      print(line)

  return rc


if __name__ == "__main__":
  sys.exit(main())
