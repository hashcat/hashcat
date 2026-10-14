#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The DES string-to-key of RFC 3961 6.2, shared by the encryption types des-cbc-crc (1),
# des-cbc-md4 (2) and des-cbc-md5 (3), so for one password and salt all three give the same key.
# The password followed by the salt is fanfolded into eight bytes, given odd parity and corrected
# away from the weak keys, and that key runs a DES-CBC-MAC over the same buffer as both key and IV.

from Crypto.Cipher import DES

WEAK_DES_KEYS = {
  bytes.fromhex("0101010101010101"), bytes.fromhex("1f1f1f1f0e0e0e0e"),
  bytes.fromhex("e0e0e0e0f1f1f1f1"), bytes.fromhex("fefefefefefefefe"),
  bytes.fromhex("01fe01fe01fe01fe"), bytes.fromhex("1fe01fe00ef10ef1"),
  bytes.fromhex("01e001e001f101f1"), bytes.fromhex("1ffe1ffe0efe0efe"),
  bytes.fromhex("011f011f010e010e"), bytes.fromhex("e0fee0fef1fef1fe"),
  bytes.fromhex("fe01fe01fe01fe01"), bytes.fromhex("e01fe01ff10ef10e"),
  bytes.fromhex("e001e001f101f101"), bytes.fromhex("fe1ffe1ffe0efe0e"),
  bytes.fromhex("1f011f010e010e01"), bytes.fromhex("fee0fee0fef1fef1"),
}


def rev7(b):
  return sum(((b >> i) & 1) << (6 - i) for i in range(7))


def key_correction(key):
  for i in range(8):
    key[i] = (key[i] & ~1) | (0 if bin(key[i] & 0xfe).count("1") % 2 else 1)

  if bytes(key) in WEAK_DES_KEYS:
    key[7] ^= 0xf0


def string_to_key(password, salt):
  s = password + salt
  n_s = len(s) + (-len(s) % 8)
  s = bytearray(s.ljust(n_s, b"\0"))
  s_copy = bytes(s)

  tempkey = bytearray(8)

  for i in range(n_s // 8):
    blk = bytearray(x & 0x7f for x in s[i * 8:i * 8 + 8])

    if i % 2:
      blk = bytearray(rev7(blk[7 - j]) for j in range(8))

    for j in range(8):
      tempkey[j] ^= blk[j]

  for j in range(8):
    tempkey[j] = (tempkey[j] << 1) & 0xff

  key_correction(tempkey)

  mac = DES.new(bytes(tempkey), DES.MODE_CBC, iv=bytes(tempkey)).encrypt(s_copy)[-8:]

  out = bytearray(mac)

  key_correction(out)

  return bytes(out)
