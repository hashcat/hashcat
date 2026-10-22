#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes, split_hash_word

# RACF KDFAES Passphrase. A memory-hard construction over a custom PBKDF2-HMAC-SHA256 (each pass also
# returns a 16 byte carry salt): 2^(rfactor-5) passes fill an accumulator, a second pass mixes it, and
# the final key AES-256-ECB encrypts the EBCDIC username. a2e maps ASCII to EBCDIC.

A2E = bytes.fromhex(
  "00010203372d2e2f1605250b0c0d0e0f101112133c3d322618193f271c1d1e1f"
  "404f7f7b5b6c507d4d5d5c4e6b604b61f0f1f2f3f4f5f6f7f8f97a5e4c7e6e6f"
  "7cc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e94ae05a5f6d"
  "79818283848586878889919293949596979899a2a3a4a5a6a7a8a9c06ad0a107"
  "202122232415061728292a2b2c090a1b30311a333435360838393a3b04143ee1"
  "4142434445464748495152535455565758596263646566676869707172737475"
  "767778808a8b8c8d8e8f909a9b9c9d9e9fa0aaabacadaeafb0b1b2b3b4b5b6b7"
  "b8b9babbbcbdbebfcacbcccdcecfdadbdcdddedfeaebecedeeeffafbfcfdfeff")


def module_constraints():
  return [[9, 100], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _pbkdf2_racf(key, salt, iterations):
  # perl's Digest::SHA hmac_sha256 (data, key), so the python call is hmac.new (key, data).
  dk = hmac.new(key, salt + struct.pack(">I", 1), hashlib.sha256).digest()
  u = dk
  newsalt = b""

  for i in range(1, iterations):
    u = hmac.new(key, u, hashlib.sha256).digest()
    dk = bytes(a ^ b for a, b in zip(dk, u))

    if i == iterations - 2:
      newsalt = u[:16]

  return dk, newsalt


def module_generate_hash(word, salt, iterations=None):
  rfactor = 8
  rounds = 50

  if (salt or "") == "":
    random_salt = random_bytes(16)
    user = "HASHCAT"
  else:
    _sig, user, header_hex, salt_hex, _hash_hex = salt.split("*")
    random_salt = bytes.fromhex(salt_hex)
    rfactor = int(header_hex[18:20], 16)
    rounds = int(header_hex[20:24], 16)

  loops = 2 ** (rfactor - 5)
  iters = rounds * 100

  ebcdic_pw = bytes(A2E[b] for b in word)

  # The trailer is the password bit length as a 64-bit big-endian integer. The perl oracle wrote it
  # as 7 zero bytes plus one low byte, which only holds for passwords up to 31 bytes; the kernel uses
  # the full width, so a longer password sets the higher bytes.
  K = hashlib.sha256(ebcdic_pw).digest() + struct.pack(">Q", len(word) * 8)

  ebcdic_user = bytes(A2E[ord(c)] for c in user.upper())
  ebcdic_user += b"\x40" * (8 - len(user))

  acc = [b""] * loops
  cursalt = random_salt + struct.pack(">I", loops)

  for cnt in range(loops):
    tmp_hash, newsalt = _pbkdf2_racf(K, cursalt, iters)
    acc[cnt] = tmp_hash
    cursalt = newsalt + tmp_hash

  md = acc[loops - 1]

  for i in range(loops):
    idx = md[31] & (loops - 1)
    md, _ = _pbkdf2_racf(md, acc[idx], 1)
    acc[i] = md

  combined_salt = b"".join(acc[i] for i in range(loops - 1))

  aes_key, _ = _pbkdf2_racf(md, combined_salt, iters)

  user_padded = ebcdic_user + b"\x00" * 24

  cipher_text = AES.new(aes_key, AES.MODE_ECB).encrypt(user_padded[:16])

  header = "E7D7E66D0001400000%02X%04X00100010" % (rfactor, rounds)

  return "$racf-kdfaes$*%s*%s*%s*%s" % (
    user.upper(), header, random_salt.hex().upper(), cipher_text.hex().upper())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if len(hash_in.split("*")) != 5:
    return None

  return (module_generate_hash(word, hash_in), word)
