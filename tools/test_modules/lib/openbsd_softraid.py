#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What m38800.py and m38810.py have in common, which is everything but the KDF that turns the
# passphrase into the mask key. That is PKCS #5 PBKDF2 for a volume created before OpenBSD 6.1 and
# bcrypt_pbkdf since, and sr_crypto_genkdf_type in the metadata says which.
#
# sr_crypto_decrypt_key () of sys/dev/softraid_crypto.c decrypts the 32 sector keys of 64 bytes
# each in AES-256-ECB under the mask key, and sr_crypto_calculate_check_hmac_sha1 () checks them
# with an HMAC-SHA1 over all 2048 bytes, keyed with the SHA1 of the mask key.

import hashlib
import hmac

from Crypto.Cipher import AES

from .bcrypt_pbkdf import bcrypt_pbkdf
from .test_helpers import random_bytes, random_number, split_hash_word

KDF_PBKDF2 = 1
KDF_BCRYPT = 3

SALT_LEN    = 128
KEYS_LEN    = 32 * 64
MASKKEY_LEN = 32

SIGNATURE = "$openbsd-softraid$"


def _mask_key(kdf, word, salt, iterations):
  if kdf == KDF_PBKDF2:
    return hashlib.pbkdf2_hmac("sha1", word, salt, iterations, MASKKEY_LEN)

  return bcrypt_pbkdf(word, salt, iterations, MASKKEY_LEN)


def _check_hmac(mask_key, keys):
  return hmac.new(hashlib.sha1(mask_key).digest(), keys, hashlib.sha1).digest()


def generate_hash(kdf, word, salt, iterations, masked=None):
  salt = salt.encode("latin-1") if isinstance(salt, str) else salt

  mask_key = _mask_key(kdf, word, salt, iterations)

  cipher = AES.new(mask_key, AES.MODE_ECB)

  # a fresh volume gets random sector keys. On the verify path the masked keys come from the line,
  # and a wrong candidate unmasks them into keys whose HMAC differs from the one the line carries.

  if masked is None:
    keys = random_bytes(KEYS_LEN)

    masked = cipher.encrypt(keys)
  else:
    keys = cipher.decrypt(masked)

  check = _check_hmac(mask_key, keys)

  return "%s%d$%s$%s$%s$%d" % (SIGNATURE, iterations, salt.hex(), masked.hex(), check.hex(), kdf)


def verify_hash(kdf, line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith(SIGNATURE):
    return None

  fields = hash_in[len(SIGNATURE):].split("$")

  # a line without the kdf field is a PBKDF2 one, the only kind before OpenBSD 6.1

  if len(fields) == 4:
    fields.append(str(KDF_PBKDF2))

  if len(fields) != 5:
    return None

  iterations, salt, masked, _, line_kdf = fields

  if int(line_kdf) != kdf:
    return None

  if len(salt) != SALT_LEN * 2 or len(masked) != KEYS_LEN * 2:
    return None

  return (generate_hash(kdf, word, bytes.fromhex(salt), int(iterations), bytes.fromhex(masked)), word)


def random_iterations(kdf):
  # A count of 1 leaves the loop kernel unlaunched, so it is drawn as often as the general case.
  # bcrypt_pbkdf is pure Python here and costs about a third of a second per round, so its rounds
  # stay low. hashcat reads the count from the line either way.

  if random_number(0, 1) == 0:
    return 1

  if kdf == KDF_PBKDF2:
    return random_number(2, 1000)

  return random_number(2, 4)
