#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Cipher import AES

try:
  from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
except ImportError:
  from cryptography.hazmat.primitives.ciphers.algorithms import Camellia

from cryptography.hazmat.primitives.ciphers import Cipher, modes

from lib.test_helpers import random_bytes, random_number, split_hash_word

# FreeBSD GELI. The passphrase goes through PBKDF2-HMAC-SHA512 over the provider's salt, and the
# result through an HMAC-SHA512 under an empty key, which is the user key. That key gives two more:
# HMAC-SHA512(user key, 0x01) decrypts a master key slot and HMAC-SHA512(user key, 0x00) keys the
# HMAC the slot is checked with. A slot holds the Data-Key, the IV-Key and that HMAC over the two.
#
# The metadata is always encrypted in CBC under a zero IV, with AES-XTS falling back to AES-CBC,
# which is what g_eli_crypto_decrypt () of sys/geom/eli/g_eli_crypto.c does.

AES_CBC      = 11
NULL_CBC     = 16
CAMELLIA_CBC = 21
AES_XTS      = 22

SALT_LEN      = 64
DATAIVKEY_LEN = 128
MKEY_LEN      = 192
MAX_MKEYS     = 2

ZERO_IV = b"\x00" * 16

# each algorithm with each key length g_eli_keylen () takes, and the null cipher at the 512 bits
# it defaults to

COMBOS = [
  (AES_XTS,      128),
  (AES_XTS,      256),
  (AES_CBC,      128),
  (AES_CBC,      192),
  (AES_CBC,      256),
  (CAMELLIA_CBC, 128),
  (CAMELLIA_CBC, 192),
  (CAMELLIA_CBC, 256),
  (NULL_CBC,     512),
]


def _hmac(key, msg):
  return hmac.new(key, msg, hashlib.sha512).digest()


def _cbc(ealgo, key, data, encrypt):
  if ealgo == AES_XTS:
    ealgo = AES_CBC

  if ealgo == NULL_CBC:
    return data

  if ealgo == AES_CBC:
    cipher = AES.new(key, AES.MODE_CBC, ZERO_IV)

    return cipher.encrypt(data) if encrypt else cipher.decrypt(data)

  context = Cipher(Camellia(key), modes.CBC(ZERO_IV))

  operation = context.encryptor() if encrypt else context.decryptor()

  return operation.update(data) + operation.finalize()


def _user_key(word, salt, iterations):
  # eli_genkey_passphrase (): with -i 0 there is no PBKDF2 and the salt and the passphrase are
  # what the HMAC gets instead

  if iterations > 0:
    derived = hashlib.pbkdf2_hmac("sha512", word, salt, iterations, 64)
  else:
    derived = salt + word

  return _hmac(b"", derived)


def _slot(user_key, ealgo, keylen, dataiv):
  plain = dataiv + _hmac(_hmac(user_key, b"\x00"), dataiv)

  return _cbc(ealgo, _hmac(user_key, b"\x01")[:keylen // 8], plain, True)


def _opens(word, ealgo, keylen, keys, iterations, salt, mkeys):
  user_key = _user_key(word, salt, iterations)

  enc_key = _hmac(user_key, b"\x01")[:keylen // 8]
  hmac_key = _hmac(user_key, b"\x00")

  for nkey in range(MAX_MKEYS):
    if (keys & (1 << nkey)) == 0:
      continue

    plain = _cbc(ealgo, enc_key, mkeys[nkey * MKEY_LEN:(nkey + 1) * MKEY_LEN], False)

    if _hmac(hmac_key, plain[:DATAIVKEY_LEN]) == plain[DATAIVKEY_LEN:]:
      return True

  return False


def module_constraints():
  return [[0, 256], [SALT_LEN, SALT_LEN], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, ealgo=None, keylen=None, keys=None,
                         mkeys=None, version=7, aalgo=0):
  # the salt of a provider is 64 bytes, which the engine hands over as the string it drew and
  # module_verify_hash () as the bytes the line carried

  salt = salt.encode("latin-1") if isinstance(salt, str) else salt

  if iterations is None:
    # the three regimes of eli_genkey_passphrase (): no PKCS#5v2 at all, one iteration, which
    # leaves the loop kernel unused as well, and the general case

    choice = random_number(0, 2)

    iterations = choice if choice < 2 else random_number(2, 1000)

  if ealgo is None:
    ealgo, keylen = COMBOS[random_number(0, len(COMBOS) - 1)]

  if keys is None:
    keys = random_number(1, (1 << MAX_MKEYS) - 1)

  if mkeys is None:
    # a slot nothing points to is random on disk as well, since geli init fills both and encrypts
    # only the one it defines

    user_key = _user_key(word, salt, iterations)

    out = bytearray(random_bytes(MAX_MKEYS * MKEY_LEN))

    for nkey in range(MAX_MKEYS):
      if keys & (1 << nkey):
        dataiv = random_bytes(DATAIVKEY_LEN)

        out[nkey * MKEY_LEN:(nkey + 1) * MKEY_LEN] = _slot(user_key, ealgo, keylen, dataiv)

    mkeys = bytes(out)
  elif not _opens(word, ealgo, keylen, keys, iterations, salt, mkeys):
    # the candidate does not open this provider, so the line has to come back different from the
    # one that went in, or a decrypt followed by an encrypt would report every password as correct

    user_key = _user_key(word, salt, iterations)

    mkeys = _slot(user_key, ealgo, keylen, bytes(DATAIVKEY_LEN)) * MAX_MKEYS

  return "$geli$0$%d$%d$%d$%d$%d$%d$%s$%s" % (version, ealgo, keylen, aalgo, keys, iterations,
                                              salt.hex(), mkeys.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) != 11 or fields[1] != "geli" or fields[2] != "0":
    return None

  version, ealgo, keylen, aalgo, keys, iterations = (int(f) for f in fields[3:9])

  salt, mkeys = fields[9], fields[10]

  if len(salt) != SALT_LEN * 2 or len(mkeys) != MAX_MKEYS * MKEY_LEN * 2:
    return None

  return (module_generate_hash(word, bytes.fromhex(salt), iterations, ealgo, keylen, keys,
                               bytes.fromhex(mkeys), version, aalgo), word)
