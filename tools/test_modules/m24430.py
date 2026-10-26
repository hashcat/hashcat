#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import pack_hex, random_bytes, split_hash_word, utf16be

# PKCS#12 MAC, SHA-1 ($pkcs12$1). The HMAC key comes from the RFC 7292 Appendix B KDF with the
# diversifier id set to 3. SHA-1 already produces the 20 bytes that key needs, so one block covers
# it and the I/B expansion the KDF describes for longer keys never runs. The kernel widens each
# password byte into a UTF-16BE code unit rather than decoding UTF-8, which is what latin-1 below
# reproduces.

MAC_ALGO = "1"
KEY_LEN  = 20

V = 64


def module_constraints():
  return [[0, 48], [16, 40], [-1, -1], [-1, -1], [-1, -1]]


def _digest(data):
  return hashlib.sha1(data).digest()


def _mac_key(word, salt_bin, iterations):
  pwd_utf16 = utf16be(word, "latin-1") + b"\x00\x00"

  D = b"\x03" * V

  S = b""

  if len(salt_bin) > 0:
    S = (salt_bin * (V // len(salt_bin) + 1))[:V]

  v2 = ((len(pwd_utf16) + V - 1) // V) * V

  P = (pwd_utf16 * (v2 // len(pwd_utf16) + 1))[:v2]

  h = _digest(D + S + P)

  for _ in range(1, iterations):
    h = _digest(h)

  return h[:KEY_LEN]


def module_generate_hash(word, salt, iterations=None, data=None):
  iterations = 2048 if iterations is None else int(iterations)

  salt_bin = pack_hex(salt)

  data_bin = random_bytes(100) if data is None else pack_hex(data)

  mac_key = _mac_key(word, salt_bin, iterations)

  computed_mac = hmac.new(mac_key, data_bin, hashlib.sha1).digest()

  return "$pkcs12$%s$%d$%d$%s$%d$%s$%s" % (MAC_ALGO, iterations, len(salt_bin), salt_bin.hex(),
                                           len(data_bin), data_bin.hex(), computed_mac.hex())


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_in, word = res

  fields = hash_in.split("$")

  if len(fields) != 9:
    return None

  signature, mac_algo, iterations, _, salt, _, data, _ = fields[1:]

  if signature != "pkcs12":
    return None

  if mac_algo != MAC_ALGO:
    return None

  return (module_generate_hash(word, salt, iterations, data), word)
