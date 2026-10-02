#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_rc4 import hmac_md5, ntlm_key, rc4
from lib.test_helpers import random_bytes

# Kerberos 5 AS-REP (krb5asrep, etype 23). Same RC4-HMAC key schedule as krb5tgs with a different
# message type and cleartext ticket; verify keeps the decrypted ticket only when its ASN.1 markers
# match one of the accepted shapes.

MSG_TYPE = b"\x08\x00\x00\x00"

CLEARTEXT_TICKET = (
  "7981df3081dca01b3019a003020117a112041071e026814da2"
  "3f129f0e67a01b73f79aa11c301a3018a003020100a111180f32303138313033303039353"
  "831365aa206020460fdc6caa311180f32303337303931343032343830355aa40703050050"
  "c10000a511180f32303138313033303039353831365aa611180f323031383130333030393"
  "53831365aa711180f32303138313033303139353831365aa811180f323031383130333131"
  "30303433385aa90d1b0b545952454c4c2e434f5250aa20301ea003020101a11730151b066"
  "b72627467741b0b545952454c4c2e434f5250"
)


def module_constraints():
  return [[0, 256], [16, 16], [0, 27], [16, 16], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user_principal_name=None,
                         checksum=None, edata2=None):
  if user_principal_name is None:
    user_principal_name = "user@domain.com"

  k = ntlm_key(word)
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

    correct = (ticket[16:20] == "7981" and ticket[22:24] == "30") or \
              (ticket[16:18] == "79" and ticket[20:22] == "30") or \
              (ticket[16:20] == "7982" and ticket[24:26] == "30")

    cleartext = ticket if correct else "0" * (len(cleartext) + 16)

  edata2 = rc4(k3, bytes.fromhex(cleartext))

  return "$krb5asrep$23$%s:%s$%s" % (user_principal_name, checksum.hex(), edata2.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  # the hash is $krb5asrep$23$upn : checksum $ edata2, so it carries its own colon before the word

  first, rest = line[:idx].decode(errors="replace"), line[idx + 1:]

  idx2 = rest.find(b":")

  if idx2 < 0:
    return None

  second, word = rest[:idx2].decode(errors="replace"), rest[idx2 + 1:]

  data = first.split("$")

  if len(data) != 4 or data[1] != "krb5asrep":
    return None

  user_principal_name = data[3]

  data2 = second.split("$")

  if len(data2) != 2:
    return None

  checksum, edata2 = data2[0], data2[1]

  if len(checksum) != 32 or len(edata2) < 64:
    return None

  return (module_generate_hash(word, user_principal_name=user_principal_name, checksum=checksum,
                               edata2=edata2), word)
