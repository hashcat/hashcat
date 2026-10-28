#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES
from Crypto.Hash import MD5
from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 AS-REQ Pre-Auth with des-cbc-md5 (etype 3). The key is the RFC 3961 6.2
# string-to-key, and the PA-ENC-TIMESTAMP is wrapped as RFC 3961 6.2.3 says: a confounder,
# the MD5 of the whole plaintext with the checksum field zeroed, and the padded timestamp,
# DES-CBC encrypted under a zero IV.

ZERO_IV = b"\x00" * 8

# PA-ENC-TS-ENC: SEQUENCE { [0] GeneralizedTime "20190101000000Z", [1] INTEGER 123456 }
CLEARTEXT_TIMESTAMP = "301aa011180f32303139303130313030303030305aa105020301e240"


def _encrypt(key, data):
  return DES.new(key, DES.MODE_CBC, ZERO_IV).encrypt(data)


def _decrypt(key, data):
  return DES.new(key, DES.MODE_CBC, ZERO_IV).decrypt(data)


def _wrap(key, msg):
  confounder = random_bytes(8)

  plain = confounder + b"\x00" * 16 + msg + b"\x00" * (-len(msg) % 8)

  return _encrypt(key, plain[:8] + MD5.new(plain).digest() + plain[24:])


def _unwraps(key, cipher):
  plain = _decrypt(key, cipher)

  # the timestamp starts at byte 24 (after 8 confounder + 16 MD5) and must open with
  # a SEQUENCE tag (0x30)

  if plain[24] != 0x30:
    return False

  return MD5.new(plain[:8] + b"\x00" * 16 + plain[24:]).digest() == plain[8:24]


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(
  word, salt=None, iterations=None, user="user", realm="realm", data=None
):
  key = string_to_key(word, (realm.upper() + user).encode())

  if data is None:
    cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TIMESTAMP))
  else:
    cipher = bytes.fromhex(data)

    if not _unwraps(key, cipher):
      cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TIMESTAMP))

  return f"$krb5pa$3${user}${realm}${cipher.hex()}"


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 6 or fields[1] != "krb5pa" or fields[2] != "3":
    return None

  user, realm, data = fields[3], fields[4], fields[5]

  if len(data) < 64 or len(data) % 16:
    return None

  return (module_generate_hash(word, user=user, realm=realm, data=data), word)
