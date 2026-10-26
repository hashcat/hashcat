#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

# Veeam VBK. PBKDF2-HMAC-SHA1 of the UTF-16LE password gives an AES-256 key and iv that CBC encrypt a
# marker whose tail is twelve 0x0c bytes. The kernel decodes the UTF-8 password rather than widening
# it, and there is no optimized kernel, so the charset is always UTF-8.

PLAIN = b"\x30\x30\x30\x30" + b"\x0c" * 12


def module_constraints():
  return [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, ct=None):
  iterations = 10000 if iterations is None else int(iterations)

  salt_bin = bytes.fromhex(salt)

  word_utf16le = word.decode("utf-8").encode("utf-16-le")

  pbkdf2key = hashlib.pbkdf2_hmac("sha1", word_utf16le, salt_bin, iterations, 48)

  key = pbkdf2key[0:32]
  iv = pbkdf2key[32:48]

  if ct is not None:
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes.fromhex(ct))

    if pt[4:16] != b"\x0c" * 12:
      pt = b"\xff" * 16
  else:
    pt = PLAIN

  ct_bin = AES.new(key, AES.MODE_CBC, iv).encrypt(pt)

  return "$vbk$*%s*%d*%s" % (salt_bin.hex(), iterations, ct_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[:5] != "$vbk$":
    return None

  data = hash_in.split("*")

  if len(data) != 4:
    return None

  _, salt, iterations, ct = data

  return (module_generate_hash(word, salt, int(iterations), ct), word)
