#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# PDF standard security handler (RC4) for modes 10400 to 10500: the key is derived from the password
# padded to 32 bytes, the O entry, the permissions and the document id, and it encrypts the padding
# (or, at revision 3+, a digest of it, with 19 extra RC4 passes).

import hashlib
import struct

PADDING = bytes([
  0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
  0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
])


def compute_key(word, doc_id, o, p, r, enc):
  data = word + PADDING[:32 - len(word)] + bytes.fromhex(o) + struct.pack("<i", p) + bytes.fromhex(doc_id)

  if r >= 4 and not enc:
    data += struct.pack("<i", -1)

  res = hashlib.md5(data).digest()

  if r >= 3:
    for _ in range(50):
      res = hashlib.md5(res).digest()

  return res
