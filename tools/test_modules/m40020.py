#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.test_helpers import split_hash_word

# Drupal 7: 2^cost rounds of sha512 over the running digest and the password, from sha512(salt.pass),
# then the phpass base64 of the digest cut to 43 characters, behind $S$ and the cost character.

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
  return [[0, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  cost = 14 if iterations is None or iterations == "" else int(iterations)

  digest = hashlib.sha512(salt.encode() + word).digest()

  for _ in range(1 << cost):
    digest = hashlib.sha512(digest + word).digest()

  return "$S$%s%s%s" % (ITOA64[cost], salt, encode64(digest)[:43])


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if not hash_in.startswith("$S$") or len(hash_in) < 12:
    return None

  return (module_generate_hash(word, hash_in[4:12], ITOA64.find(hash_in[3])), word)
