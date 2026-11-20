#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import CAST

from lib import gpg
from lib.test_helpers import random_bytes, random_number

# GPG symmetric secret key protection with CAST5 in CFB. The S2K is SHA-1 either way, but the
# mode has two shapes and a run covers both: iterated and salted, which carries a count, and
# plain salted, which is one SHA-1 over salt and password.

S2K_HASH     = "sha1"
S2K_HASH_ID  = 2
CIPHER_ALGO  = 3
KEY_LEN      = 16
IV_LEN       = 8
MODULUS_SIZE = 4096

# module_17040.c accepts 256 to 3072 hex characters of protected data, so 128 to 1536 bytes, and
# the last 20 of those are the SHA-1 checksum the kernel decides on.

DATA_MIN = 128
DATA_MAX = 1536


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [0, 256],
      },
      'optimized': None,
      'combined_length': None,
      'association_parameters': [{"iterations": 0}, {"iterations": (50000, 60000)}],
    },
  }


def _cfb(key, iv):
  return CAST.new(key, CAST.MODE_CFB, IV=iv, segment_size=64)


def _body_len():
  # Whether cast128_decrypt_cfb () steps a block past the payload depends on the data length
  # modulo 8, and only at the maximum does that block reach past the buffers. Drawn uniformly the
  # maximum would come up about once in 1400 hashes, so it is picked outright one time in eight,
  # as gpg.sym_payload_len () does for the symmetric modes.

  pick = random_number(0, 7)

  if pick == 0:
    return DATA_MIN - 20

  if pick == 1:
    return DATA_MAX - 20

  return random_number(DATA_MIN - 20, DATA_MAX - 20)


def _key(word, salt, s2k_type, count):
  if s2k_type == gpg.S2K_ITERATED:
    return gpg.s2k_iterated(word, salt, count, KEY_LEN, S2K_HASH)

  return gpg.s2k_salted(word, salt, KEY_LEN, S2K_HASH)


def module_generate_hash(word, salt, iterations=None):
  if iterations is None:
    iterated = random_number(0, 1) == 1
    count = random_number(50000, 60000) if iterated else 0
  else:
    count = int(iterations)
    iterated = count > 0

  s2k_type = gpg.S2K_ITERATED if iterated else gpg.S2K_SALTED

  salt_raw = random_bytes(8)

  # The IV comes from the salt and the password, not from the generator, for the reason
  # lib/gpg.py gives in aes_cfb_generate (): module_17040.c takes the IV as the digest, and the
  # two hashes of a SHARED_SALT pair are drawn from one generator state, so a drawn IV would come
  # out equal for both and the pair would reach hashcat as one hash instead of two on one salt.
  # SHA-256 rather than the mode's own SHA-1, because the plain salted S2K derives the key as
  # sha1 (salt || password) too, and an IV drawn that way would be the first half of the key.

  iv = hashlib.sha256(salt_raw + word).digest()[:IV_LEN]

  key  = _key(word, salt_raw, s2k_type, count)
  body = random_bytes(_body_len())

  plain = body + hashlib.sha1(body).digest()

  return gpg.build(_cfb(key, iv).encrypt(plain), MODULUS_SIZE, s2k_type,
                   S2K_HASH_ID, CIPHER_ALGO, iv, count, salt_raw)


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    fields = gpg.parse(hash_in.decode("ascii"))
  except UnicodeDecodeError:
    return None

  if fields is None:
    return None

  if fields["hash_id"] != S2K_HASH_ID or fields["cipher_algo"] != CIPHER_ALGO:
    return None

  if len(fields["iv"]) != IV_LEN:
    return None

  key   = _key(word, fields["salt"], fields["s2k_type"], fields["count"])
  plain = _cfb(key, fields["iv"]).decrypt(fields["data"])

  if len(plain) < 20 or hashlib.sha1(plain[:-20]).digest() != plain[-20:]:
    return None

  digest = gpg.build(_cfb(key, fields["iv"]).encrypt(plain), fields["modulus_size"],
                     fields["s2k_type"], S2K_HASH_ID, CIPHER_ALGO, fields["iv"],
                     fields["count"], fields["salt"])

  return (digest, word)
