#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

# IBM AS/400 SSHA1: sha1 of the user name (10 chars, space padded, upper cased) and the password,
# both widened to UTF-16BE. The user name is the salt.


def module_constraints():
  return [[0, 256], [1, 10], [-1, -1], [-1, -1], [-1, -1]]


def as400_ssha1(username, password):
  username = (username + " " * 10)[:10]

  salt_be = username.upper().encode("utf-16-be")
  word_be = password.decode("latin-1").encode("utf-16-be")

  return hashlib.sha1(salt_be + word_be).hexdigest()


def module_generate_hash(word, salt, iterations=None):
  return "$as400$ssha1$*%s*%s" % (salt.upper(), as400_ssha1(salt.upper(), word).upper())


def module_verify_hash(line):
  parts = line.split(b":", 1)

  if len(parts) < 2:
    return None

  fields = parts[0].split(b"*")

  if len(fields) < 2 or fields[0] != b"$as400$ssha1$":
    return None

  return (module_generate_hash(parts[1], fields[1].decode()), parts[1])
