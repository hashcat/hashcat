#!/usr/bin/env python3

# Author......: See docs/credits.txt
# License.....: MIT

# Extracts a hashcat -m 2200 hash from an EncFS 1.x volume, read from the .encfs6.xml file at the
# root of its encrypted directory. The line is the one John the Ripper's encfs2john.py writes,
# without the leading folder name.

import base64
import binascii
import os
import sys

from xml.etree import ElementTree


def _text(root, tag):
  node = root.find(".//" + tag)

  if node is None:
    return None

  if node.text is None:
    return None

  return "".join(node.text.split())


def process(path):
  if os.path.isdir(path) is True:
    path = os.path.join(path, ".encfs6.xml")

  try:
    root = ElementTree.parse(path).getroot()
  except (OSError, ElementTree.ParseError) as e:
    sys.stderr.write("%s: %s\n" % (path, e))
    return

  cipher     = _text(root, "cipherAlg/name")
  key_size   = _text(root, "keySize")
  iterations = _text(root, "kdfIterations")
  salt_len   = _text(root, "saltLen")
  salt_data  = _text(root, "saltData")
  data_len   = _text(root, "encodedKeySize")
  data       = _text(root, "encodedKeyData")

  if None in (cipher, key_size, iterations, salt_len, salt_data, data_len, data):
    sys.stderr.write("%s: not an EncFS 1.x configuration\n" % path)
    return

  numbers = (key_size, iterations, salt_len, data_len)

  if any(n.isdigit() is False for n in numbers):
    sys.stderr.write("%s: keySize, kdfIterations, saltLen or encodedKeySize is not a number\n" % path)
    return

  if cipher.lower().find("aes") == -1:
    sys.stderr.write("%s: cipher %s is not supported, only AES\n" % (path, cipher))
    return

  if int(iterations) == 0:
    sys.stderr.write("%s: volumes without PBKDF2 (kdfIterations 0) are not supported\n" % path)
    return

  try:
    salt = base64.b64decode(salt_data)
    blob = base64.b64decode(data)
  except binascii.Error:
    sys.stderr.write("%s: saltData or encodedKeyData is not base64\n" % path)
    return

  if (len(salt) != int(salt_len)) or (len(blob) != int(data_len)):
    sys.stderr.write("%s: saltLen or encodedKeySize does not match its data\n" % path)
    return

  sys.stdout.write("$encfs$%d*%d*0*%d*%s*%d*%s\n" % (int(key_size), int(iterations), len(salt),
                                                      salt.hex(), len(blob), blob.hex()))


if __name__ == "__main__":
  if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <EncFS directory or .encfs6.xml> [...]\n" % sys.argv[0])
    sys.exit(1)

  for arg in sys.argv[1:]:
    process(arg)
