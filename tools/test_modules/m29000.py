#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import kernel_charset, random_mixedcase_string, random_number, utf16le

# sha1($salt.sha1(utf16le($username).':'.utf16le($pass))), the salt and the user name in hex. The
# two kernel families convert the password to UTF-16 differently, see kernel_charset ().

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 256], [0, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, user=None):
  if user is None:
    user = random_mixedcase_string(random_number(0, 256 // 2)).encode()

  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  inner = hashlib.sha1(user.decode("latin-1").encode("utf-16-le") + b":" + utf16le(word, CHARSET)).digest()

  return "%s:%s:%s" % (hashlib.sha1(salt_bytes + inner).hexdigest(), salt_bytes.hex(), user.hex())


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4:
    return None

  digest, salt, user = (p.decode(errors="replace") for p in parts[:3])

  word = parts[3]

  if not re.fullmatch(r"[0-9a-fA-F]{40}", digest):
    return None

  if not re.fullmatch(r"[0-9a-fA-F]{0,256}", salt) or not re.fullmatch(r"[0-9a-fA-F]{0,256}", user):
    return None

  return (module_generate_hash(word, bytes.fromhex(salt), None, bytes.fromhex(user)), word)
