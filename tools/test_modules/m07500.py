#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import time

from lib.kerberos_rc4 import hmac_md5, ntlm_key, rc4
from lib.test_helpers import random_bytes

# Kerberos 5 AS-REQ Pre-Auth (krb5pa, etype 23). The RC4 key encrypts the PA-ENC-TIMESTAMP; on the
# verify path the stored ciphertext is decrypted and kept only when its timestamp is 14 digits.

MSG_TYPE = b"\x01\x00\x00\x00"


def get_random_kerberos5_salt(custom_salt):
  clear_data = random_bytes(14) + time.strftime("%Y%m%d%H%M%S", time.localtime()).encode("ascii") + random_bytes(8)

  return "user$realm$salt$%s$%s$" % (custom_salt.hex(), clear_data.hex())


def module_constraints():
  return [[0, 256], [16, 16], [0, 27], [16, 16], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if "$" not in salt:
    salt = get_random_kerberos5_salt(salt.encode("latin-1"))

  arr = salt.split("$")

  user, realm, salt_field = arr[0], arr[1], arr[2]

  hmac_salt = arr[3]
  hmac_salt_bin = bytes.fromhex(hmac_salt)

  clear_data = arr[4]

  k = ntlm_key(word)
  k1 = hmac_md5(k, MSG_TYPE)
  k3 = hmac_md5(k1, hmac_salt_bin)

  if len(clear_data) > 1:
    hash_buf = rc4(k3, bytes.fromhex(clear_data))
  else:
    hash_bin = bytes.fromhex(arr[5])

    decrypted = rc4(k3, hash_bin)

    timestamp = decrypted[14:28]

    is_numeric = len(timestamp) == 14 and all(0x30 <= b <= 0x39 for b in timestamp)

    if not is_numeric:
      hash_buf = b"\x00" * 36

      if hash_buf == hash_bin:
        hash_buf = b"\x01" * 36
    else:
      hash_buf = hash_bin

  return "$krb5pa$23$%s$%s$%s$%s%s" % (user, realm, salt_field, hash_buf.hex(), hmac_salt)


def module_verify_hash(line):
  # walk the four dollar fields the way perl does, then find the colon after the last one

  s = line.decode("latin-1")

  index1 = s.find("$", 11)
  if index1 < 1:
    return None

  index2 = s.find("$", index1 + 1)
  if index2 < 1:
    return None

  index3 = s.find("$", index2 + 1)
  if index3 < 1:
    return None

  colon = s.find(":", index3 + 1)
  if colon < 1:
    return None

  hash_in = s[:colon]
  word = line[colon + 1:]

  salt = hash_in[11:index3 + 1]
  salt += hash_in[colon - 32:] + "$$"
  salt += hash_in[index3 + 1:colon - 32]

  return (module_generate_hash(word, salt), word)
