#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Kerberos 5 etype 23 (RC4-HMAC) key schedule, shared by the krb5pa, krb5tgs and krb5asrep modes.
# The NT hash keys HMAC-MD5 over a fixed message type, and that keys HMAC-MD5 over the checksum to
# make the RC4 key.

import hashlib
import hmac as _hmac

from Crypto.Cipher import ARC4
from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, utf16le


def ntlm_key(word):
  return MD4.new(utf16le(word, kernel_charset())).digest()


def hmac_md5(key, msg):
  return _hmac.new(key, msg, hashlib.md5).digest()


def rc4(key, data):
  return ARC4.new(key).encrypt(data)


def k1_k3(word, msg_type, checksum):
  # perl's Digest::HMAC_MD5::hmac_md5 takes the message first and the key second, so the NT hash keys
  # HMAC over the message type, and k1 keys HMAC over the checksum. msg_type is the four byte
  # little-endian usage.

  k = ntlm_key(word)

  k1 = hmac_md5(k, msg_type)

  k3 = hmac_md5(k1, checksum)

  return k1, k3
