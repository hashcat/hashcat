#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import DES
from Crypto.Hash import MD4

from lib.des_key import setup_des_key
from lib.test_helpers import (kernel_charset, random_bytes, random_lowercase_string, random_number,
                              random_numeric_string, random_uppercase_string, utf16le)

# NetNTLMv1 / NetNTLMv1+ESS: the NT hash, padded to 21 bytes, as three DES keys over the first 8
# bytes of md5(server challenge . client challenge). The two kernel families convert the password
# to UTF-16 differently, see kernel_charset (); MD4 is pycryptodome's, because hashlib often has
# none.

CHARSET = kernel_charset()


def random_name(count):
  out = ""

  for _ in range(count):
    kind = random_number(1, 3)

    if kind == 1:
      out += random_numeric_string(1)
    elif kind == 2:
      out += random_uppercase_string(1)
    else:
      out += random_lowercase_string(1)

  return out


def random_netntlmv1_salt(len_user, len_domain):
  user = random_name(len_user)
  domain = random_name(len_domain)

  c_challenge = random_bytes(8)
  s_challenge = random_bytes(8)

  return user + "::" + domain + ":" + c_challenge.hex() + s_challenge.hex()


def module_constraints():
  return [[0, 127], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, ntlm_salt=None):
  if ntlm_salt is None:
    len_user = random_number(0, 15)

    ntlm_salt = random_netntlmv1_salt(len_user, random_number(0, 15))

  idx1 = ntlm_salt.find("::")
  user = ntlm_salt[:idx1]
  idx2 = ntlm_salt.find(":", idx1 + 2)
  domain = ntlm_salt[idx1 + 2:idx2]

  if len(ntlm_salt) - (idx2 + 1) > 32:
    c_challenge_hex = ntlm_salt[idx2 + 1:idx2 + 1 + 48]
    idx2 += 32
  else:
    c_challenge_hex = ntlm_salt[idx2 + 1:idx2 + 1 + 16] + "0" * 32

  c_challenge = bytes.fromhex(c_challenge_hex[:16])

  s_challenge_hex = ntlm_salt[idx2 + 17:idx2 + 17 + 16]

  challenge = hashlib.md5(bytes.fromhex(s_challenge_hex) + c_challenge).digest()[:8]

  nthash = MD4.new(utf16le(word, CHARSET)).digest() + b"\x00" * 5

  ntresp = b"".join(DES.new(setup_des_key(nthash[i:i + 7]), DES.MODE_ECB).encrypt(challenge) for i in (0, 7, 14))

  return "%s::%s:%s:%s:%s" % (user, domain, c_challenge_hex, ntresp.hex(), s_challenge_hex)


def module_verify_hash(line):
  # the user name can be empty, which the perl verify did not allow for

  idx1 = line.find(b"::")

  if idx1 < 0:
    return None

  idx2 = line.find(b":", idx1 + 2)

  if idx2 < 1:
    return None

  idx2 = line.find(b":", idx2 + 1)

  if idx2 < 1:
    return None

  ntlm_salt = line[:idx2 - 32]

  idx2 = line.find(b":", idx2 + 1)

  if idx2 < 1:
    return None

  ntlm_salt += line[idx2 + 1:idx2 + 1 + 16]

  word = line[idx2 + 1 + 16 + 1:]

  try:
    return (module_generate_hash(word, None, None, ntlm_salt.decode()), word)
  except ValueError:
    return None
