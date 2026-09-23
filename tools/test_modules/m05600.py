#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from Crypto.Hash import MD4

from lib.test_helpers import kernel_charset, random_count, random_hex_string, random_string, utf16le

# NetNTLMv2. The NT hash is MD4 of the UTF-16LE password, which the two kernel families convert
# differently, see kernel_charset (); MD4 is pycryptodome's, because hashlib often has none.

CHARSET = kernel_charset()


def random_client_challenge():
  return "0101000000000000" + random_hex_string(2 * 16) + "00000000" + random_hex_string(2 * random_count(20)) + "00"


def module_constraints():
  return [[0, 127], [0, 55], [0, 27], [0, 27], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, domain=None, srv_ch=None, cli_ch=None):
  user = salt

  if domain is None:
    domain = random_string(27 - len(user))

  if srv_ch is None:
    srv_ch = random_hex_string(2 * 8)

  if cli_ch is None:
    cli_ch = random_client_challenge()

  nthash = MD4.new(utf16le(word, CHARSET)).digest()

  # perl's uc () folds ASCII only in a byte string, and so does bytes.upper ()

  identity = (user.encode().upper() + domain.encode()).decode("latin-1").encode("utf-16-le")

  key = hmac.new(nthash, identity, hashlib.md5).digest()

  digest = hmac.new(key, bytes.fromhex(srv_ch) + bytes.fromhex(cli_ch), hashlib.md5).hexdigest()

  return "%s::%s:%s:%s:%s" % (user, domain, srv_ch, digest, cli_ch)


def module_verify_hash(line):
  idx1 = line.find(b"::")

  if idx1 == -1:
    return None

  idx2 = line.find(b":", idx1 + 2)

  if idx2 == -1:
    return None

  idx3 = line.find(b":", idx2 + 3 + 16 + 32)

  if idx3 == -1:
    return None

  user   = line[:idx1].decode()
  domain = line[idx1 + 2:idx2].decode()
  srv_ch = line[idx2 + 1:idx2 + 1 + 16].decode()
  cli_ch = line[idx2 + 3 + 16 + 32:idx3].decode()
  word   = line[idx3 + 1:]

  try:
    return (module_generate_hash(word, user, None, domain, srv_ch, cli_ch), word)
  except ValueError:
    return None
