#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What m37900.py, m37901.py and m37902.py have in common, which is everything but the hash the key
# generator runs.
#
# A BestCrypt container (.jbc) stores one 256 byte key slot per password. The slot holds an
# encrypted key block, then an 8 byte IV in clear. The password goes through the PKCS#12 key
# derivation of RFC 7292 appendix B with ID 1, at a block size of 64 bytes whatever the hash is,
# and the result decrypts the key block with AES-256 in CBC or in XTS. The first 90 bytes of the
# decrypted block are hashed again, and the first 32 bytes of that are stored at offset 96, which
# is what tells a trial decryption that the password was right.

import hashlib

from Crypto.Cipher import AES

from . import whirlpool
from .test_helpers import random_bytes, random_number
from .xts import Xts

SHA256    = 128
SHA512    = 10
WHIRLPOOL = 129

HLEN = {SHA256: 32, SHA512: 64, WHIRLPOOL: 64}

MODE_CBC = 0xBC000002
MODE_XTS = 0xBC000004

ITERATIONS = 1000

SLOT_LEN   = 256
BLOCK_LEN  = 128
BODY_LEN   = 90
DIGEST_OFF = 96
DIGEST_LEN = 32

V = 64


def _hash(hash_id, data):
  if hash_id == SHA256:    return hashlib.sha256(data).digest()
  if hash_id == SHA512:    return hashlib.sha512(data).digest()
  if hash_id == WHIRLPOOL: return whirlpool.whirlpool(data)

  raise ValueError(hash_id)


def _fill(length, filler):
  # the PKCS#12 fill: repeat the filler, truncating the last copy

  out = bytearray()

  while len(out) < length:
    out += filler[0:length - len(out)]

  return bytes(out)


def _add(a, b):
  # a and b are big endian numbers of the same width

  total = (int.from_bytes(a, "big") + int.from_bytes(b, "big")) % (1 << (len(a) * 8))

  return total.to_bytes(len(a), "big")


def _derive(hash_id, iterations, word, salt_raw, keylen):
  hlen = HLEN[hash_id]

  # the password is widened one byte per character and carries its terminator, which is how the
  # kernel reads it as well

  pwd = word.decode("latin-1").encode("utf-16-be") + b"\x00\x00"

  # SHA-256 takes as many password blocks as the password needs. For the two 64 byte digests the
  # key generator fixes the password block at one block, which holds 32 characters, so two
  # passwords of 32 or more that begin with the same 32 derive the same key there.

  v2 = ((len(pwd) + V - 1) // V) * V if hash_id == SHA256 else V

  diversifier = b"\x01" * V

  salt_block = _fill(V,  salt_raw)
  pwd_block  = _fill(v2, pwd)

  out = bytearray()

  while True:
    digest = _hash(hash_id, diversifier + salt_block + pwd_block)

    for _ in range(1, iterations):
      digest = _hash(hash_id, digest)

    out += digest[0:min(keylen - len(out), hlen)]

    if len(out) >= keylen: break

    block = _add(_fill(V, digest), (1).to_bytes(V, "big"))

    salt_block = _add(salt_block, block)
    pwd_block  = _add(pwd_block[0:V], block) + pwd_block[V:]

  return bytes(out)


def _crypt(mode_id, key, iv, data, encrypt):
  if mode_id == MODE_XTS:
    # the tweak of the first block is the 8 byte IV followed by zeros, which is that value read as
    # a little endian data unit number

    cipher = Xts("aes", key[0:32], key[32:64])

    sequence = int.from_bytes(iv, "little")

    return cipher.encrypt(data, sequence) if encrypt == True else cipher.decrypt(data, sequence)

  # CBC repeats the 8 byte IV to fill the 16 byte block

  cipher = AES.new(key[0:32], AES.MODE_CBC, iv=iv + iv)

  return cipher.encrypt(data) if encrypt == True else cipher.decrypt(data)


def generate_hash(hash_id, word, salt, iterations=None, source=None, modes=(MODE_CBC, MODE_XTS)):
  salt_raw = bytes.fromhex(salt)

  if iterations is None: iterations = ITERATIONS

  iv_off = BLOCK_LEN if hash_id == SHA256 else 160

  if source is None:
    mode_id = modes[random_number(0, len(modes) - 1)]

    slot = bytearray(random_bytes(SLOT_LEN))

    body = bytes(slot[0:DIGEST_OFF])

    pt = body + _hash(hash_id, body[0:BODY_LEN])[0:DIGEST_LEN]
  else:
    mode_id, slot = source[0], bytearray(source[1])

    pt = None

  keylen = 64 if mode_id == MODE_XTS else 32

  key = _derive(hash_id, iterations, word, salt_raw, keylen)

  iv = bytes(slot[iv_off:iv_off + 8])

  if pt is None:
    pt = _crypt(mode_id, key, iv, bytes(slot[0:BLOCK_LEN]), False)

    if _hash(hash_id, pt[0:BODY_LEN])[0:DIGEST_LEN] != pt[DIGEST_OFF:BLOCK_LEN]:
      return None

  slot[0:BLOCK_LEN] = _crypt(mode_id, key, iv, pt, True)

  return "$BestCrypt$1$5$3$%d$240$%d$%d$%d$%s$1$%s" % (
    iterations,
    mode_id,
    hash_id,
    len(salt_raw),
    salt_raw.hex(),
    bytes(slot).hex())


def verify_hash(hash_id, line, modes=(MODE_CBC, MODE_XTS)):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  fields = hash_in.split(b"$")

  if len(fields) != 13:
    return None

  if fields[1] != b"BestCrypt":
    return None

  if (fields[2], fields[3], fields[4]) != (b"1", b"5", b"3"):
    return None

  if fields[6] != b"240":
    return None

  if fields[11] != b"1":
    return None

  try:
    iterations = int(fields[5])
    mode_id    = int(fields[7])
    salt_size  = int(fields[9])
    salt       = fields[10].decode("ascii")
    slot       = bytes.fromhex(fields[12].decode("ascii"))
  except (UnicodeDecodeError, ValueError):
    return None

  if int(fields[8]) != hash_id:
    return None

  if mode_id not in modes:
    return None

  if (salt_size > V) or (len(salt) != salt_size * 2):
    return None

  if len(slot) != SLOT_LEN:
    return None

  digest = generate_hash(hash_id, word, salt, iterations, (mode_id, slot), modes)

  if digest is None:
    return None

  return (digest, word)
