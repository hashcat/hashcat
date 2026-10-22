#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

from lib.test_helpers import split_hash_word

# Kerberos 5 AS-REQ Pre-Auth with AES256-CTS-HMAC-SHA1-96 (etype 18). Key derivation is
# PBKDF2-HMAC-SHA1 then the RFC 3961 DK function, encryption is AES in CBC-CS3 ciphertext
# stealing form and the checksum is HMAC-SHA1 truncated to 12 bytes.
#
# The perl oracle decrypts the supplied timestamp but its 'check_correct' is redeclared inside
# the enc_timestamp block, so the outer copy stays 0 and the decrypted value is always thrown
# away. The output is therefore fixed by the key alone: a constant cleartext, its checksum, and
# the CTS re-encryption. We reproduce that effective behaviour.

ETYPE = "18"
KEYSIZE = 32

ZERO_IV = b"\x00" * 16

KERBEROS_NFOLDED = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")
# nfold of 0x0000000155 and 0x00000001aa to 16 bytes
NFOLDED_KI = bytes.fromhex("5b582c160a5aa80556ab55aad5402ab5")
NFOLDED_KE = bytes.fromhex("ae2c160b04ad5006ab55aad56a80355a")

CLEARTEXT_TICKET = (
  "68c8459f3f10c851b8827118bb459c6e301aa011180f323031"
  "32313131363134323835355aa10502030c28a2"
)


def _cbc_enc(data, key):
  return AES.new(key, AES.MODE_CBC, ZERO_IV).encrypt(data)


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def _pad(n, size):
  # perl (~n + 1) & (size - 1), the number of zero nibbles to top up the last block
  return (-n) & (size - 1)


def _dk(nfolded, key):
  # RFC 3961 DK/DR: encrypt the folded constant, feeding each output block back in as the
  # plaintext for the next, until KEYSIZE bytes are produced.
  out = _cbc_enc(nfolded, key)

  while len(out) < KEYSIZE:
    out = out + _cbc_enc(out[-16:], key)

  return out[:KEYSIZE]


def module_constraints():
  return [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm",
                         checksum=None, enc_timestamp=None, format=None):
  # three layouts: 1 is hashcat's, 2 is krb5pa-sha1 with an empty salt field, 3 is
  # krb5pa-sha1 with the salt filled in. Layout alternates on the salt so a sweep covers all.
  salt_given = salt is not None and len(salt) > 0

  if format is None:
    format = ((int(salt[0]) % 3) + 1) if salt_given else 1

  mysalt = salt if format == 3 else (realm.upper() + user)

  b_seed = hashlib.pbkdf2_hmac("sha1", word, mysalt.encode(), 4096, KEYSIZE)

  b_key_bytes = _dk(KERBEROS_NFOLDED, b_seed)

  b_ki = _dk(NFOLDED_KI, b_key_bytes)
  b_ke = _dk(NFOLDED_KE, b_key_bytes)

  cleartext_ticket = CLEARTEXT_TICKET

  checksum = hmac.new(b_ki, bytes.fromhex(cleartext_ticket), hashlib.sha1).digest()[:12].hex()

  len_cleartext_last_block = len(cleartext_ticket) % 32
  cleartext_last_block = cleartext_ticket[-len_cleartext_last_block:]

  padding = _pad(len(cleartext_ticket), 32)

  b_cleartext_last_block_padded = bytes.fromhex(cleartext_last_block + "0" * padding)

  # encrypt up to and including block n-1
  truncated_cleartext_ticket = cleartext_ticket[:-len_cleartext_last_block]

  b_truncated_enc_ticket = _cbc_enc(bytes.fromhex(truncated_cleartext_ticket), b_ke)

  b_enc_ticket_n_1_block = b_truncated_enc_ticket[-16:]

  b_enc_last_block = b_enc_ticket_n_1_block[:len_cleartext_last_block // 2]

  # craft the new n-1 block
  b_enc_ticket_n_1_block = _cbc_enc(_xor(b_enc_ticket_n_1_block, b_cleartext_last_block_padded), b_ke)

  b_enc_timestamp = b_truncated_enc_ticket[:-16] + b_enc_ticket_n_1_block + b_enc_last_block

  edata_hex = b_enc_timestamp.hex()

  if format == 3:
    return "$krb5pa$%s$%s$%s$%s$%s%s" % (ETYPE, user, realm, salt, edata_hex, checksum)

  if format == 2:
    return "$krb5pa$%s$%s$%s$$%s%s" % (ETYPE, user, realm, edata_hex, checksum)

  return "$krb5pa$%s$%s$%s$%s%s" % (ETYPE, user, realm, edata_hex, checksum)


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  data = hash_str.split("$")

  if len(data) not in (6, 7):
    return None

  signature, algorithm, user, realm = data[1:5]

  if len(data) == 7:
    salt, edata = data[5], data[6]
  else:
    salt, edata = None, data[5]

  if signature != "krb5pa":
    return None

  if algorithm != ETYPE:
    return None

  if len(edata) < 88 or len(edata) > 112:
    return None

  checksum = edata[-24:]
  enc_timestamp = edata[:-24]

  if salt is not None:
    format = 3 if len(salt) else 2
  else:
    format = 1

  return (module_generate_hash(word, salt=salt, user=user, realm=realm, checksum=checksum,
                               enc_timestamp=enc_timestamp, format=format), word)
