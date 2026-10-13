#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_des import string_to_key
from lib.test_helpers import split_hash_word

# Kerberos 5 etype 3 (des-cbc-md5 key from the DB): the string-to-key of RFC 3961 6.2 over the
# password followed by uppercase(realm)+user. That one function serves etypes 1, 2 and 3, so the
# three keys are the same and -m 38400, -m 38401 and -m 38402 share a kernel.


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, user="user", realm="realm"):
  mysalt = (realm.upper() + user).encode()

  key = string_to_key(word, mysalt)

  return "$krb5db$3$%s$%s$%s" % (user, realm, key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 5 or fields[1] != "krb5db" or fields[2] != "3":
    return None

  return (module_generate_hash(word, None, None, fields[3], fields[4]), word)
