#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Streebog (GOST R 34.11-2012) for the 117xx and 118xx test modules.
#
# gostcrypto returns the digest in little endian order and the kernels compare big endian, so every
# digest here is reversed before it is printed.
#
# gostcrypto's update () is only correct while what it has been fed is a whole number of 64 byte
# blocks, so the message always goes in whole, in the constructor.

import hmac

import gostcrypto


def _new(name):
  def factory(data=b""):
    return gostcrypto.gosthash.new(name, data=bytearray(data))

  return factory


def digest(bits, data):
  return bytes(_new("streebog%d" % bits)(data).digest())[::-1].hex()


def hmac_digest(bits, key, msg):
  return hmac.new(key, msg, _new("streebog%d" % bits)).digest()[::-1].hex()
