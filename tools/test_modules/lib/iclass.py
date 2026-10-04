#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The HID iClass key-diversification MAC, shared by 36900 (Standard) and 36901 (Legacy). It is the
# cipher state machine from the iClass reader protocol: 12 card/reader nonce bytes clock the state,
# then four more bytes are read out of register r, MSB first, and each MAC byte is bit-reflected.


def reflect8(b):
  b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
  b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
  b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)

  return b & 0xFF


def successor(k, t, l, r, b, y_bit):
  r0 = (r >> 7) & 1
  r4 = (r >> 3) & 1
  r7 = r & 1

  tt = (((t >> 15) & 1) ^ ((t >> 14) & 1) ^ ((t >> 10) & 1) ^ ((t >> 8) & 1)
        ^ ((t >> 5) & 1) ^ ((t >> 4) & 1) ^ ((t >> 1) & 1) ^ (t & 1))

  bt = ((b >> 6) & 1) ^ ((b >> 5) & 1) ^ ((b >> 4) & 1) ^ (b & 1)

  nt = ((t >> 1) | (((tt ^ r0 ^ r4) & 1) << 15)) & 0xFFFF
  nb = ((b >> 1) | (((bt ^ r7) & 1) << 7)) & 0xFF

  r1 = (r >> 6) & 1
  r2 = (r >> 5) & 1
  r3 = (r >> 4) & 1
  r5 = (r >> 2) & 1
  r6 = (r >> 1) & 1

  z0 = (r0 & r2) ^ (r1 & (r3 ^ 1)) ^ (r2 | r4)
  z1 = (r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ tt ^ y_bit
  z2 = (r3 & (r5 ^ 1)) ^ (r4 & r6) ^ r7 ^ tt

  sel = ((z0 & 1) << 2) | ((z1 & 1) << 1) | (z2 & 1)
  val = (k[sel] ^ nb) & 0xFF

  nl = (val + l + r) & 0xFF
  nr = (val + l) & 0xFF

  return (nt, nl, nr, nb)


def mac(rev_ccnr, div_key):
  t = 0xE012
  l = ((div_key[0] ^ 0x4C) + 0xEC) & 0xFF
  r = ((div_key[0] ^ 0x4C) + 0x21) & 0xFF
  b = 0x4C

  for i in range(12):
    rb = rev_ccnr[i]

    for bit in range(7, -1, -1):
      t, l, r, b = successor(div_key, t, l, r, b, (rb >> bit) & 1)

  out = [0, 0, 0, 0]

  for i in range(4):
    for bit in range(7, -1, -1):
      out[i] |= ((r >> 2) & 1) << bit
      t, l, r, b = successor(div_key, t, l, r, b, 0)

  return (reflect8(out[0]) << 24) | (reflect8(out[1]) << 16) | (reflect8(out[2]) << 8) | reflect8(out[3])
