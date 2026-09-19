#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# XTS over a 16 byte block cipher, which is how VeraCrypt encrypts the header the m2001x modules
# build. No package on PyPI offers the mode over Twofish or Serpent, and the mode is short, so the
# ciphers come from pycryptodome and from pytwofish.py and pyserpent.py beside this file, and the
# chaining is here.
#
# Whole blocks only. A VeraCrypt data unit is 512 bytes, so the ciphertext stealing that IEEE 1619
# defines for a trailing partial block never comes up.

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

from pyserpent import Serpent
from pytwofish import Twofish


class _Aes:
  def __init__(self, key):
    self.cipher = AES.new(key, AES.MODE_ECB)

  def encrypt(self, block):
    return self.cipher.encrypt(block)

  def decrypt(self, block):
    return self.cipher.decrypt(block)


CIPHERS = {"aes": _Aes, "serpent": Serpent, "twofish": Twofish}


def _next_tweak(tweak):
  # the tweak of the next block, the last one multiplied by the primitive element of GF(2 ** 128)

  value = int.from_bytes(tweak, "little") << 1

  if value >> 128:
    value = (value & ((1 << 128) - 1)) ^ 0x87

  return value.to_bytes(16, "little")


class Xts:
  def __init__(self, cipher, key_main, key_tweak):
    self.data  = CIPHERS[cipher](key_main)
    self.tweak = CIPHERS[cipher](key_tweak)

  def _run(self, step, data, sequence):
    tweak = self.tweak.encrypt(sequence.to_bytes(16, "little"))

    out = bytearray()

    for off in range(0, len(data), 16):
      out  += strxor(step(strxor(data[off:off + 16], tweak)), tweak)
      tweak = _next_tweak(tweak)

    return bytes(out)

  def encrypt(self, data, sequence):
    return self._run(self.data.encrypt, data, sequence)

  def decrypt(self, data, sequence):
    return self._run(self.data.decrypt, data, sequence)
