#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

import hashlib

from Crypto.Cipher import AES

# RAR3-hp (password protected header). The AES-128 key comes from a 0x40000 round SHA1 over the
# UTF-16LE password and salt, with RAR's quirk of hashing the buffer while an in-place SHA1 rewrites
# it, and every 0x4000th round contributes one IV byte. The key is the byte swapped first 16 bytes
# of the final digest. The check value is the first 16 bytes of AES-CBC over a fixed block.

ITERATIONS = 0x40000

MASK = 0xffffffff

FIXED_RAW_STRING = bytes.fromhex("c43d7b00400700000000000000000000")


def _rotl32(x, n):
  return ((x << n) | (x >> (32 - n))) & MASK


def _mangle_block(block):
  # RAR hashes the password buffer with a SHA1 that also overwrites it, one 64 byte block at a time.
  # The rewritten block is words W[64..79] of the SHA1 message schedule, which depends only on the
  # input bytes, so the hash state is not needed here.

  w = [int.from_bytes(block[k * 4:k * 4 + 4], "big") for k in range(16)]

  for i in range(16, 80):
    w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

  return b"".join(w[64 + k].to_bytes(4, "little") for k in range(16))


def _sha1_update_rar29(ctx, buf, length, count):
  ctx.update(bytes(buf))

  j = count & 63

  if (j + length) <= 63:
    return

  i = 64 - j

  if (i + 63) >= length:
    return

  while (i + 63) < length:
    buf[i:i + 64] = _mangle_block(buf[i:i + 64])

    i += 64


def _derive(word, salt):
  # No IS_OPTIMIZED switch here, the oracle always widens each password byte to UTF-16LE.
  buf = bytearray(word.decode("latin-1").encode("utf-16-le") + salt)

  length = len(buf)
  count  = 0

  ctx = hashlib.sha1()
  iv  = b""

  for i in range(ITERATIONS):
    _sha1_update_rar29(ctx, buf, length, count)

    count += length

    ctx.update(struct.pack("<I", i)[0:3])

    count += 3

    if (i & 0x3fff) == 0:
      iv += ctx.copy().digest()[19:20]

  k = ctx.digest()

  # byte swap the first four 32 bit words into the AES-128 key
  key = b"".join(k[t * 4:t * 4 + 4][::-1] for t in range(4))

  return key, iv


def module_constraints():
  return [[0, 128], [8, 8], [0, 20], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  key, iv = _derive(word, salt)

  hash_buf = AES.new(key, AES.MODE_CBC, iv).encrypt(FIXED_RAW_STRING)

  return "$RAR3$*0*%s*%s" % (salt.hex(), hash_buf[0:16].hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  if hash_in[0:9] != "$RAR3$*0*":
    return None

  idx2 = hash_in.find("*", 9)

  if idx2 < 1:
    return None

  salt = bytes.fromhex(hash_in[9:idx2])

  new_hash = module_generate_hash(word, salt)

  return (new_hash, word)
