#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The 56 to 64 bit DES key spread the LM and NetNTLMv1 modes use, without setting parity bits: DES
# ignores them.


def setup_des_key(key_56):
  k = key_56

  return bytes([
    k[0],
    ((k[0] << 7) | (k[1] >> 1)) & 255,
    ((k[1] << 6) | (k[2] >> 2)) & 255,
    ((k[2] << 5) | (k[3] >> 3)) & 255,
    ((k[3] << 4) | (k[4] >> 4)) & 255,
    ((k[4] << 3) | (k[5] >> 5)) & 255,
    ((k[5] << 2) | (k[6] >> 6)) & 255,
    (k[6] << 1) & 255,
  ])
