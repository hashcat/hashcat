#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# MS Office 2007/2010/2013 key derivation, for modes 9400/9500/9600: H(salt.utf16le(pass)), then
# iterations of H(counter.previous), the counter a 4 byte little endian integer.

import struct


def iterated_key(hashfn, salt_bin, word_utf16, iterations):
  tmp = hashfn(salt_bin + word_utf16).digest()

  for i in range(iterations):
    tmp = hashfn(struct.pack("<I", i) + tmp).digest()

  return tmp
