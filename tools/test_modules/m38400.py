#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_des import string_to_key
from lib.test_helpers import split_hash_word

# Kerberos 5, the key of a DES encryption type as a domain database holds it: the string-to-key of
# RFC 3961 6.2 over the password followed by uppercase(realm)+user. That one function serves etypes
# 1, 2 and 3, so the key is the same for all three and the mode reads the three signatures.

ETYPES = (1, 2, 3)


def module_constraints():
  return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, user="user", realm="realm", etype=None):
  mysalt = (realm.upper() + user).encode()

  key = string_to_key(word, mysalt)

  # the type follows the key, so two equal passwords give two equal lines, of which hashcat keeps
  # one. The shift drops the parity bit, which left in skews the residue against type 1.

  if etype is None:
    etype = ETYPES[(key[0] >> 1) % len(ETYPES)]

  return "$krb5db$%d$%s$%s$%s" % (etype, user, realm, key.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 5 or fields[1] != "krb5db":
    return None

  if fields[2] not in ("1", "2", "3"):
    return None

  return (module_generate_hash(word, None, None, fields[3], fields[4], int(fields[2])), word)
