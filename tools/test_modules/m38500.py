#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES
from Crypto.Hash import MD5

from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 TGS-REP with des-cbc-md5 (etype 3). The key is the RFC 3961 6.2 string-to-key, the same
# one mode 38400 compares against, and the ticket is wrapped as RFC 3961 6.2.3 says: a confounder,
# the MD5 of the whole plaintext with the checksum field zeroed, and the padded ticket, DES-CBC
# encrypted under a zero IV. On verify the stored ciphertext is decrypted and kept only when the
# ASN.1 markers and the checksum both hold, so a wrong password does not round trip into a false
# positive.

ZERO_IV = b"\x00" * 8

CLEARTEXT_TICKET = (
  "6381b03081ada00703050050a00000a11b3019a003020117a1"
  "12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5"
  "44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201"
  "01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353"
  "134343735305aa711180f32303136303231363030343735305aa811180f32303136303232"
  "323134343735305a"
)


def _encrypt(key, data):
  return DES.new(key, DES.MODE_CBC, ZERO_IV).encrypt(data)


def _decrypt(key, data):
  return DES.new(key, DES.MODE_CBC, ZERO_IV).decrypt(data)


def _wrap(key, ticket):
  confounder = random_bytes(8)

  plain = confounder + b"\x00" * 16 + ticket + b"\x00" * (-len(ticket) % 8)

  return _encrypt(key, plain[:8] + MD5.new(plain).digest() + plain[24:])


def _unwraps(key, cipher):
  plain = _decrypt(key, cipher)

  # the two ASN.1 markers the kernel rejects on before it spends an MD5, then the checksum itself

  if plain[24] != 0x63:
    return False

  if not ((plain[25] == 0x81 and plain[27] == 0x30) or plain[25] == 0x82):
    return False

  if plain[32:35] != b"\x03\x05\x00" and plain[32:36] != b"\xa0\x07\x03\x05":
    return False

  return MD5.new(plain[:8] + b"\x00" * 16 + plain[24:]).digest() == plain[8:24]


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm",
                         spn="test/spn", checksum=None, edata2=None):
  key = string_to_key(word, (realm.upper() + user).encode())

  if edata2 is None:
    cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TICKET))
  else:
    cipher = bytes.fromhex(checksum + edata2)

    if not _unwraps(key, cipher):
      cipher = _wrap(key, bytes(len(CLEARTEXT_TICKET) // 2))

  return "$krb5tgs$3$*%s$%s$%s*$%s$%s" % (user, realm, spn, cipher[:16].hex(), cipher[16:].hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 8 or fields[1] != "krb5tgs" or fields[2] != "3":
    return None

  user, realm, spn, checksum, edata2 = fields[3][1:], fields[4], fields[5][:-1], fields[6], fields[7]

  if len(checksum) != 32 or len(edata2) < 64 or len(edata2) % 16:
    return None

  return (module_generate_hash(word, user=user, realm=realm, spn=spn, checksum=checksum,
                               edata2=edata2), word)
