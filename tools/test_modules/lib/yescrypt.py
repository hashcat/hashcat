#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The crypt base64 that yescrypt ($y$, $gy$) and scrypt ($7$) settings are written in, for the modes
# whose hash comes from libc crypt () through crypt_r.

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def encode64(data):
  out = []

  i = 0

  while i < len(data):
    val = data[i]
    i += 1
    bits = 8

    if i < len(data):
      val |= data[i] << 8
      i += 1
      bits += 8

    if i < len(data):
      val |= data[i] << 16
      i += 1
      bits += 8

    while bits > 0:
      out.append(ITOA64[val & 0x3f])
      val >>= 6
      bits -= 6

  return "".join(out)


def decode64(s):
  out = bytearray()

  i = 0

  while i < len(s):
    val = 0
    bits = 0
    j = 0

    while j < 4 and i < len(s):
      val |= ITOA64.index(s[i]) << (6 * j)
      i += 1
      j += 1
      bits += 6

    for _ in range(bits // 8):
      out.append(val & 0xff)
      val >>= 8

  return bytes(out)


def encode_uint(value, length):
  return "".join(ITOA64[(value >> (6 * i)) & 0x3f] for i in range(length))


def decode_uint(s):
  return sum(ITOA64.index(c) << (6 * i) for i, c in enumerate(s))
