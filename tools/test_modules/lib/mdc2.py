#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MDC-2 over DES, as OpenSSL computes it: the last partial block is zero padded and nothing else is
# appended. Neither hashlib nor pycryptodome carries MDC-2, so this builds it on pycryptodome's DES.

from Crypto.Cipher import DES


def _xor(a: bytes, b: bytes) -> bytes:
  return bytes(x ^ y for x, y in zip(a, b))


def mdc2(data: bytes) -> bytes:
  h  = b"\x52" * 8
  hh = b"\x25" * 8

  if (len(data) % 8) != 0: data = data + b"\x00" * (8 - (len(data) % 8))

  for off in range(0, len(data), 8):
    m = data[off:off + 8]

    # bits 5 and 6 of the first key byte are forced to 10 and 01, so the two keys always differ

    k1 = bytes([(h[0]  & 0x9f) | 0x40]) + h[1:]
    k2 = bytes([(hh[0] & 0x9f) | 0x20]) + hh[1:]

    e1 = _xor(m, DES.new(k1, DES.MODE_ECB).encrypt(m))
    e2 = _xor(m, DES.new(k2, DES.MODE_ECB).encrypt(m))

    h  = e1[0:4] + e2[4:8]
    hh = e2[0:4] + e1[4:8]

  return h + hh
