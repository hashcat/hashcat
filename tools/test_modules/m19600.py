#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 TGS-REP with AES128-CTS-HMAC-SHA1-96 (etype 17). The key is derived with
# PBKDF2-HMAC-SHA1 then the RFC 3961 DK function, encryption is AES in CBC-CS3 ciphertext
# stealing form and the checksum is HMAC-SHA1 truncated to 12 bytes over a confounder plus
# ticket. AES128 needs a single 16 byte DK block, so no key folding beyond the first block.

ETYPE = "17"
KEYSIZE = 16

ZERO_IV = b"\x00" * 16

KERBEROS_NFOLDED = bytes.fromhex("6b65726265726f737b9b5b2b93132b93")
NFOLDED_KI = bytes.fromhex("62dc6e371a63a80958ac562b15404ac5")
NFOLDED_KE = bytes.fromhex("b5b0582c14b6500aad56ab55aa80556a")

CLEARTEXT_TICKET = (
  "6381b03081ada00703050050a00000a11b3019a003020117a1"
  "12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5"
  "44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201"
  "01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353"
  "134343735305aa711180f32303136303231363030343735305aa811180f32303136303232"
  "323134343735305a"
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


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm",
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
    truncated_ticket_decrypted = b_truncated_ticket_decrypted.hex()

    check_correct = ((truncated_ticket_decrypted[32:36] == "6381" and
                      truncated_ticket_decrypted[38:40] == "30") or
                     (truncated_ticket_decrypted[32:36] == "6382")) and \
                    ((truncated_ticket_decrypted[48:54] == "030500") or
                     (truncated_ticket_decrypted[48:56] == "050307A0"))

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

  return "$krb5tgs$%s$%s$%s$%s$%s" % (ETYPE, user, realm, checksum.hex(), edata2.hex())


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  data = hash_str.split("$")

  if len(data) != 7:
    return None

  signature, algorithm, user, realm, checksum, edata2 = data[1:7]

  if signature != "krb5tgs":
    return None

  if algorithm != ETYPE:
    return None

  if len(checksum) != 24:
    return None

  if len(edata2) < 64:
    return None

  return (module_generate_hash(word, user=user, realm=realm, checksum=checksum, edata2=edata2),
          word)
