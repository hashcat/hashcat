#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Microsoft ConfigMgr media variables, shared by m40177.py and m40178.py. A line is $sccm$, a label
# and the first 40 bytes of the file in hex: a 24 byte header and the first ciphertext block. The
# key comes from CryptDeriveKey over the UTF-16LE password, the file is AES-CBC with a zero IV, and
# its plaintext starts with UTF-16LE "<?xml ve". The modes accept either label and go by the
# algorithm id in the header, so both labels are generated for both modes.

import hashlib
import re
import struct

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_word, utf16le

P0 = "<?xml ve".encode("utf-16-le")

LABELS = ["aes128", "aes256"]

LINE = re.compile(r"^\$sccm\$(aes128|aes256)\$([0-9a-fA-F]{80})$")


def derive_key(word, keylen):
  h = hashlib.sha1(utf16le(word)).digest()

  k0 = hashlib.sha1(bytes(b ^ 0x36 for b in h) + b"\x36" * 44).digest()
  k1 = hashlib.sha1(bytes(b ^ 0x5c for b in h) + b"\x5c" * 44).digest()

  return (k0 + k1)[0:keylen]


def generate(word, alg_id, keylen, label=None, pt_len=None, ct_len=None):
  c0 = AES.new(derive_key(word, keylen), AES.MODE_ECB).encrypt(P0)

  if label is None:
    # The label and the lengths are derived from the first ciphertext block, so the same password
    # always gives the same line. Two lines that differ only there share a digest, and hashcat would
    # print just one of them.

    n = int.from_bytes(hashlib.sha1(c0).digest()[0:4], "little")

    label = LABELS[n & 1]

    # any plaintext that fills the first block, padded to whole blocks with 1 to 16 bytes

    pt_len = 16 + (n >> 1) % 0x100000
    ct_len = (pt_len // 16 + 1) * 16

  head = b"\x00\x00\xed\xec" + struct.pack("<5I", 20, pt_len, ct_len, alg_id, 0) + c0

  return "$sccm$%s$%s" % (label, head.hex())


def verify(line, alg_id, keylen):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  m = LINE.match(hash_in)

  if m is None:
    return None

  head = bytes.fromhex(m.group(2))

  _, pt_len, ct_len, alg, _ = struct.unpack_from("<5I", head, 4)

  if alg != alg_id:
    return None

  return (generate(word, alg_id, keylen, m.group(1), pt_len, ct_len), word)
