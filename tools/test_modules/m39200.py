#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import binascii
import struct

from Crypto.Cipher import DES
from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 AS-REP with des-cbc-crc (etype 1). Same as mode 39100 (TGS-REP etype 1)
# but the ASN.1 marker at byte 12 is 0x79 (EncASRepPart) or 0x7a (EncTGSRepPart)
# instead of 0x63 (EncTicketPart).

CLEARTEXT_ASREP = (
  "7981df3081dca01b3019a003020111a1120410e2aa1c894df7"
  "23b7277eef29700bf760a11c301a3018a003020100a111180f32303233303333313132303"
  "434355aa20602041d9d970ba311180f32303337303931343032343830355aa40703050040"
  "c10000a511180f32303233303333313132303434355aa611180f323032333033333131323"
  "03434355aa711180f32303233303333313232303434355aa811180f323032333034303731"
  "32303434355aa90d1b0b4558414d504c452e434f4daa20301ea003020102a11730151b066"
  "b72627467741b0b6578616d706c652e636f6d"
)


def _encrypt(key, data):
  return DES.new(key, DES.MODE_CBC, key).encrypt(data)


def _decrypt(key, data):
  return DES.new(key, DES.MODE_CBC, key).decrypt(data)


def _crc32(data):
  # Kerberos CRC-32: init=0, no final complement (RFC 3961 section 6)
  return ~binascii.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def _wrap(key, msg):
  confounder = random_bytes(8)

  body = confounder + b"\x00" * 4 + msg
  body += b"\x00" * ((-len(body)) % 8)

  crc = _crc32(body)

  body = confounder + struct.pack("<I", crc) + msg
  body += b"\x00" * ((-len(body)) % 8)

  return _encrypt(key, body)


def _unwraps(key, cipher):
  plain = _decrypt(key, cipher)

  # ASN.1 marker at byte 12: 0x79 (EncASRepPart) or 0x7a (EncTGSRepPart)

  if plain[12] not in (0x79, 0x7A):
    return False

  stored_crc = struct.unpack("<I", plain[8:12])[0]

  check_plain = plain[:8] + b"\x00" * 4 + plain[12:]

  return _crc32(check_plain) == stored_crc


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(
  word,
  salt=None,
  iterations=None,
  user="user",
  realm="realm",
  checksum=None,
  edata2=None,
):
  key = string_to_key(word, (realm.upper() + user).encode())

  if edata2 is None:
    cipher = _wrap(key, bytes.fromhex(CLEARTEXT_ASREP))
  else:
    cipher = bytes.fromhex(checksum + edata2)

    if not _unwraps(key, cipher):
      cipher = _wrap(key, bytes(len(CLEARTEXT_ASREP) // 2))

  return f"$krb5asrep$1${user}${realm}${cipher[:16].hex()}${cipher[16:].hex()}"


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 7 or fields[1] != "krb5asrep" or fields[2] != "1":
    return None

  user, realm, checksum, edata2 = fields[3], fields[4], fields[5], fields[6]

  if len(checksum) != 32 or len(edata2) < 64 or len(edata2) % 16:
    return None

  return (
    module_generate_hash(
      word, user=user, realm=realm, checksum=checksum, edata2=edata2
    ),
    word,
  )
