#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_rc4 import hmac_md5, rc4
from lib.test_helpers import pack_hex, random_bytes

# Kerberos 5 TGS-REP (krb5tgs, etype 23), keyed straight from the NT hash. Same RC4-HMAC schedule as
# m13100, except the password field is the NT hash as hex32, so the key is that hex unpacked rather
# than MD4 of the UTF-16 password. On verify the stored edata2 is kept only when its ASN.1 markers
# check out.

MSG_TYPE = b"\x02\x00\x00\x00"

CLEARTEXT_TICKET = (
  "6381b03081ada00703050050a00000a11b3019a003020117a1"
  "12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5"
  "44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201"
  "01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353"
  "134343735305aa711180f32303136303231363030343735305aa811180f32303136303232"
  "323134343735305a"
)


def module_constraints():
  return [[32, 32], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, user=None, realm=None, spn=None,
                         checksum=None, edata2=None):
  user = "user" if user is None else user
  realm = "realm" if realm is None else realm
  spn = "test/spn" if spn is None else spn

  k = pack_hex(word)
  k1 = hmac_md5(k, MSG_TYPE)

  cleartext = CLEARTEXT_TICKET

  if checksum is not None:
    checksum = bytes.fromhex(checksum)
  else:
    nonce = random_bytes(8).hex()
    cleartext = nonce + cleartext
    checksum = hmac_md5(k1, bytes.fromhex(cleartext))

  k3 = hmac_md5(k1, checksum)

  if edata2 is not None:
    ticket = rc4(k3, bytes.fromhex(edata2)).hex()

    correct = ((ticket[16:20] == "6381" and ticket[22:24] == "30") or ticket[16:20] == "6382") and \
              (ticket[32:38] == "030500" or ticket[32:40] == "050307A0")

    cleartext = ticket if correct else "0" * (len(cleartext) + 16)

  edata2 = rc4(k3, bytes.fromhex(cleartext))

  return "$krb5tgs$23$*%s$%s$%s*$%s$%s" % (user, realm, spn, checksum.hex(), edata2.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("$")

  if len(data) != 8:
    return None

  signature = data[1]
  user = data[3][1:]
  realm = data[4]
  spn = data[5][:-1]
  checksum = data[6]
  edata2 = data[7]

  if signature != "krb5tgs" or len(checksum) != 32 or len(edata2) < 64:
    return None

  return (module_generate_hash(word, user=user, realm=realm, spn=spn, checksum=checksum,
                               edata2=edata2), word)
