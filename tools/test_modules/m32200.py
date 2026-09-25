#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 AS-REP with AES256-CTS-HMAC-SHA1-96 (etype 18). The key is derived with
# PBKDF2-HMAC-SHA1 then the RFC 3961 DK function, encryption is AES in CBC-CS3 ciphertext
# stealing form and the checksum is HMAC-SHA1 truncated to 12 bytes over a confounder plus
# ticket. AES256 needs a 32 byte key, so each DK step folds two encrypted blocks together.

ETYPE = "18"
KEYSIZE = 32

ZERO_IV = b"\x00" * 16

KERBEROS_NFOLDED = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")
NFOLDED_KI = bytes.fromhex("6b60b0582a6ba80d5aad56ab55406ad5")
NFOLDED_KE = bytes.fromhex("be349a4d24be500eaf57abd5ea80757a")

CLEARTEXT_TICKET = (
  "7981ef3081eca02b3029a003020112a12204200e97d1626616"
  "6e06252cbec52003e0f6b4f0280deec6dc58cdbf39845d6f0e77a11c301a3018a00302010"
  "0a111180f32303233303331363135353732315aa20602045b66ac3ea311180f3230333730"
  "3931343032343830355aa40703050050c10000a511180f323032333033313631353537323"
  "15aa611180f32303233303331363135353732315aa711180f323032333033313730313537"
  "32315aa811180f32303233303331373135353732315aa90d1b0b4558414d504c452e434f4"
  "daa20301ea003020101a11730151b066b72627467741b0b4558414d504c452e434f4d"
)


def _cbc_enc(data, key):
  return AES.new(key, AES.MODE_CBC, ZERO_IV).encrypt(data)


def _cbc_dec(data, key):
  return AES.new(key, AES.MODE_CBC, ZERO_IV).decrypt(data)


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


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="example.com",
                         checksum=None, edata2=None):
  mysalt = (realm.upper() + user).encode()

  b_seed = hashlib.pbkdf2_hmac("sha1", word, mysalt, 4096, KEYSIZE)

  b_key_bytes = _dk(KERBEROS_NFOLDED, b_seed)

  b_ki = _dk(NFOLDED_KI, b_key_bytes)
  b_ke = _dk(NFOLDED_KE, b_key_bytes)

  cleartext_ticket = CLEARTEXT_TICKET

  if edata2 is not None:
    len_last_block = len(edata2) % 32

    tmp = len_last_block + 32

    b_truncated_enc_ticket = bytes.fromhex(edata2[:-tmp])
    b_last_block = bytes.fromhex(edata2[-len_last_block:])
    b_n_1_block = bytes.fromhex(edata2[-tmp:][:32])

    b_truncated_ticket_decrypted = _cbc_dec(b_truncated_enc_ticket, b_ke)
    t = b_truncated_ticket_decrypted.hex()

    check_correct = ((t[32:36] in ("7981", "7a81")) and t[38:40] == "30") or \
                    ((t[32:34] in ("79", "7a")) and t[36:38] == "30") or \
                    ((t[32:36] in ("7982", "7a82")) and t[40:42] == "30")

    if check_correct:
      b_n_2 = b_truncated_enc_ticket[-16:]

      b_n_1_decrypted = _cbc_dec(b_n_1_block, b_ke)

      b_last_plain = _xor(b_n_1_decrypted[:len_last_block // 2], b_last_block)

      omitted = b_n_1_decrypted[-(16 - len_last_block // 2):]

      b_n_1 = _xor(_cbc_dec(b_last_block + omitted, b_ke), b_n_2)

      cleartext_ticket = (b_truncated_ticket_decrypted + b_n_1 + b_last_plain).hex()
    else:
      # fake/wrong ticket, otherwise decrypt then encrypt gives false positives every time
      cleartext_ticket = "0" * (len(cleartext_ticket) + 32)

  if checksum is not None:
    checksum = bytes.fromhex(checksum)
  else:
    if edata2 is None:
      cleartext_ticket = random_bytes(16).hex() + cleartext_ticket

    checksum = hmac.new(b_ki, bytes.fromhex(cleartext_ticket), hashlib.sha1).digest()[:12]

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

  edata2 = b_truncated_enc_ticket[:-16] + b_enc_ticket_n_1_block + b_enc_last_block

  return "$krb5asrep$%s$%s$%s$%s$%s" % (ETYPE, user, realm, checksum.hex(), edata2.hex())


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  data = hash_str.split("$")

  if len(data) != 7:
    return None

  signature, algorithm, user, realm, checksum, edata2 = data[1:7]

  if signature != "krb5asrep":
    return None

  if algorithm != ETYPE:
    return None

  if len(checksum) != 24:
    return None

  if len(edata2) < 64:
    return None

  return (module_generate_hash(word, user=user, realm=realm, checksum=checksum, edata2=edata2),
          word)
