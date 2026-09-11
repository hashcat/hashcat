#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os

from Crypto.Hash import MD4

# The optimized kernels widen each byte instead of decoding the UTF-8, and
# module_01000.c:58 documents that as deliberate rather than as a bug, so the two
# kernel families really do disagree on a multi byte password. The oracle follows
# whichever one test.sh is about to run: decoding as latin1 reproduces the
# widening byte for byte, decoding as utf-8 is the conversion the pure kernels do.
# test.sh exports IS_OPTIMIZED from the same value it uses to decide on -O.

PW_CHARSET = "latin1"

if os.environ.get("IS_OPTIMIZED") == "0":
  PW_CHARSET = "utf-8"

# hashlib has no MD4 wherever OpenSSL ships without the legacy provider, which is most places now.
# pycryptodome carries its own, and tools/install_modules.sh already installs it.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  utf16le = word.decode(PW_CHARSET).encode("utf-16-le")

  return MD4.new(utf16le).hexdigest()


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  return (module_generate_hash(word, None), word)
