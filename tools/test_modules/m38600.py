#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES
from Crypto.Hash import MD5

from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 AS-REP with des-cbc-md5 (etype 3). The key is the RFC 3961 6.2 string-to-key, the same
# one mode 38400 compares against, and the reply is wrapped as RFC 3961 6.2.3 says: a confounder,
# the MD5 of the whole plaintext with the checksum field zeroed, and the padded EncASRepPart,
# DES-CBC encrypted under a zero IV. On verify the stored ciphertext is decrypted and kept only when
# the ASN.1 markers and the checksum both hold, so a wrong password does not round trip into a false
# positive.

ZERO_IV = b"\x00" * 8

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
  return DES.new(key, DES.MODE_CBC, ZERO_IV).encrypt(data)


def _decrypt(key, data):
  return DES.new(key, DES.MODE_CBC, ZERO_IV).decrypt(data)


def _wrap(key, msg):
  confounder = random_bytes(8)

  plain = confounder + b"\x00" * 16 + msg + b"\x00" * (-len(msg) % 8)

  return _encrypt(key, plain[:8] + MD5.new(plain).digest() + plain[24:])


def _unwraps(key, cipher):
  plain = _decrypt(key, cipher)

  # the ASN.1 markers the kernel rejects on before it spends an MD5, then the checksum itself.
  # An EncASRepPart is application type 25 and an EncTGSRepPart 26, which RFC 4120 5.4.2 asks
  # implementations to accept here as well, and the length sits on one, two or three bytes.

  if plain[24] not in (0x79, 0x7a):
    return False

  if plain[25] < 0x80:
    ok = plain[26] == 0x30
  elif plain[25] == 0x81:
    ok = plain[27] == 0x30
  elif plain[25] == 0x82:
    ok = plain[28] == 0x30
  else:
    ok = False

  if not ok:
    return False

  return MD5.new(plain[:8] + b"\x00" * 16 + plain[24:]).digest() == plain[8:24]


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm",
                         checksum=None, edata2=None):
  key = string_to_key(word, (realm.upper() + user).encode())

  if edata2 is None:
    cipher = _wrap(key, bytes.fromhex(CLEARTEXT_ASREP))
  else:
    cipher = bytes.fromhex(checksum + edata2)

    if not _unwraps(key, cipher):
      cipher = _wrap(key, bytes(len(CLEARTEXT_ASREP) // 2))

  return "$krb5asrep$3$%s$%s$%s$%s" % (user, realm, cipher[:16].hex(), cipher[16:].hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 7 or fields[1] != "krb5asrep" or fields[2] != "3":
    return None

  user, realm, checksum, edata2 = fields[3], fields[4], fields[5], fields[6]

  if len(checksum) != 32 or len(edata2) < 64 or len(edata2) % 16:
    return None

  return (module_generate_hash(word, user=user, realm=realm, checksum=checksum, edata2=edata2),
          word)
