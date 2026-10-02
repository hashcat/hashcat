#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import split_hash_word

# KWallet uses the phpass scheme, but over the md5 hex digest of the password rather than the
# password itself. Authen::Passphrase::PHPass runs 2^cost rounds of md5 over the last digest and
# that passphrase, starting from md5 of the salt and the passphrase, and prints a standard $P$ line.

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def encode64(raw):
  out = ""

  i = 0

  while i < len(raw):
    v = raw[i]
    i += 1

    out += ITOA64[v & 0x3f]

    if i < len(raw):
      v |= raw[i] << 8

    out += ITOA64[(v >> 6) & 0x3f]

    if i >= len(raw):
      break

    i += 1

    if i < len(raw):
      v |= raw[i] << 16

    out += ITOA64[(v >> 12) & 0x3f]

    if i >= len(raw):
      break

    i += 1

    out += ITOA64[(v >> 18) & 0x3f]

  return out


def module_constraints():
  return [[0, 256], [8, 8], [0, 39], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 11 if iterations is None or iterations == "" else int(iterations)

  passphrase = hashlib.md5(word).hexdigest().encode("ascii")

  digest = hashlib.md5(salt.encode() + passphrase).digest()

  for _ in range(1 << cost):
    digest = hashlib.md5(digest + passphrase).digest()

  return "$P$" + ITOA64[cost] + salt + encode64(digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  new_hash = module_generate_hash(word, hash_in[4:12], ITOA64.find(hash_in[3:4]))

  return (hash_in[:3] + new_hash[3:], word)
