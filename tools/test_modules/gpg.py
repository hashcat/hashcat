#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What the m170x0 modules share: the OpenPGP string to key function and the $gpg$ hash string.
# What differs per mode is the cipher the secret key material is protected with and the hash the
# S2K runs, so a module passes those in.
#
# module_verify_hash rebuilds the hash out of the hash. The salt, the iteration count, the IV and
# the cipher are all carried in it, so decrypting with the key they derive and encrypting the
# result again reproduces the string byte for byte, and on the way it checks the trailing digest,
# which is what the kernel decides a candidate on.

import hashlib

from Crypto.Cipher import AES

from test_helpers import random_bytes, random_number

USAGE = 254  # the secret key usage octet that says the protected data ends in a SHA-1 checksum

S2K_SALTED   = 1
S2K_ITERATED = 3


def s2k_salted(password, salt, out_len, hashname):
  return hashlib.new(hashname, salt + password).digest()[:out_len]


def s2k_iterated(password, salt, count, out_len, hashname):
  # RFC 4880 S2K id 3: H_i = H ((0x00 * i) || the first count bytes of salt || password repeated.
  # count is the decoded byte count rather than the coded octet the packet carries.

  base = salt + password

  # m17050 streams a count in the hundreds of millions, so the hash is fed in large chunks. The
  # chunk is a whole number of repeats of base, which keeps the byte stream identical to feeding
  # one repeat at a time.

  chunk = base * (65536 // len(base) + 1)

  out = bytearray()
  i   = 0

  while len(out) < out_len:
    h = hashlib.new(hashname)

    if i:
      h.update(b"\x00" * i)

    remaining = count

    while remaining >= len(chunk):
      h.update(chunk)

      remaining -= len(chunk)

    while remaining >= len(base):
      h.update(base)

      remaining -= len(base)

    if remaining:
      h.update(base[:remaining])

    out.extend(h.digest())

    i += 1

  return bytes(out[:out_len])


def build(data, modulus_size, s2k_type, hash_id, cipher_algo, iv, count, salt):
  return "$gpg$*1*%d*%d*%s*%d*%d*%d*%d*%d*%s*%d*%s" % (
    len(data), modulus_size, data.hex(), s2k_type, USAGE, hash_id,
    cipher_algo, len(iv), iv.hex(), count, salt.hex())


def parse(hash_in):
  if not hash_in.startswith("$gpg$*1*"):
    return None

  parts = hash_in[len("$gpg$*"):].split("*")

  if len(parts) != 12:
    return None

  try:
    fields = {
      "modulus_size": int(parts[2]),
      "data":         bytes.fromhex(parts[3]),
      "s2k_type":     int(parts[4]),
      "hash_id":      int(parts[6]),
      "cipher_algo":  int(parts[7]),
      "iv":           bytes.fromhex(parts[9]),
      "count":        int(parts[10]),
      "salt":         bytes.fromhex(parts[11]),
    }
  except ValueError:
    return None

  if int(parts[1]) != len(fields["data"]):
    return None

  if int(parts[8]) != len(fields["iv"]):
    return None

  if int(parts[5]) != USAGE:
    return None

  return fields


# m17010, m17020 and m17030 differ only in the hash their S2K runs, so their body is here.
# Cipher 7 is AES-128 and cipher 9 is AES-256, which are separate kernels, so a run picks between
# them and covers both.

AES_KEY_LEN  = {7: 16, 9: 32}
AES_IV_LEN   = 16
MODULUS_SIZE = 1024
BODY_LEN     = 300


def _aes_cfb(key, iv):
  return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)


def aes_cfb_generate(word, hashname, hash_id):
  salt        = random_bytes(8)
  iv          = random_bytes(16)
  count       = random_number(1024, 65536)
  cipher_algo = 7 if random_number(0, 1) else 9

  key  = s2k_iterated(word, salt, count, AES_KEY_LEN[cipher_algo], hashname)
  body = random_bytes(BODY_LEN)

  plain = body + hashlib.sha1(body).digest()

  return build(_aes_cfb(key, iv).encrypt(plain), MODULUS_SIZE, S2K_ITERATED,
               hash_id, cipher_algo, iv, count, salt)


def aes_cfb_verify(word, fields, hashname, hash_id):
  if fields["hash_id"] != hash_id or len(fields["iv"]) != AES_IV_LEN:
    return None

  key_len = AES_KEY_LEN.get(fields["cipher_algo"])

  if key_len is None:
    return None

  key   = s2k_iterated(word, fields["salt"], fields["count"], key_len, hashname)
  plain = _aes_cfb(key, fields["iv"]).decrypt(fields["data"])

  if len(plain) < 20 or hashlib.sha1(plain[:-20]).digest() != plain[-20:]:
    return None

  return build(_aes_cfb(key, fields["iv"]).encrypt(plain), fields["modulus_size"],
               fields["s2k_type"], hash_id, fields["cipher_algo"], fields["iv"],
               fields["count"], fields["salt"])
