#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import pbkdf2_b64

# PBKDF2-HMAC-MD5: md5:iterations:base64(salt):base64(key), see lib/pbkdf2_b64.py.


def module_constraints():
  return [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, out_len=32):
  iterations = 1000 if iterations is None else int(iterations)

  return pbkdf2_b64.generate_hash("md5", "md5", word, salt, iterations, out_len)


def module_verify_hash(line):
  parsed = pbkdf2_b64.parse("md5", line)

  if parsed is None:
    return None

  salt, iterations, out_len, word = parsed

  return (module_generate_hash(word, salt, iterations, out_len), word)
