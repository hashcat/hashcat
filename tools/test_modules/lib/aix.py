#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The AIX {ssha1}, {ssha256} and {ssha512} formats: PBKDF2 of the password, written out in the crypt
# alphabet three bytes at a time, most significant byte first.

import hashlib

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def to64(v, n):
  out = ""

  for _ in range(n):
    out += ITOA64[v & 0x3f]
    v >>= 6

  return out


def encode(raw):
  out = ""

  full = len(raw) - (len(raw) % 3)

  for i in range(0, full, 3):
    out += to64((raw[i] << 16) | (raw[i + 1] << 8) | raw[i + 2], 4)

  tail = raw[full:]

  if len(tail) == 2:
    out += to64((tail[0] << 16) | (tail[1] << 8), 3)
  elif len(tail) == 1:
    out += to64(tail[0] << 16, 2)

  return out


def generate_hash(tag, algo, word, salt, iterations):
  raw = hashlib.pbkdf2_hmac(algo, word, salt.encode(), iterations)

  return "{%s}%02d$%s$%s" % (tag, iterations.bit_length() - 1, salt, encode(raw))


def verify_hash(tag, algo, line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  prefix = "{%s}" % tag

  if not hash_in.startswith(prefix):
    return None

  data = hash_in[len(prefix):].split("$")

  if len(data) != 3 or not data[0].isdigit():
    return None

  return (generate_hash(tag, algo, word, data[1], 1 << int(data[0])), word)
