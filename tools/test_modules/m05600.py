#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4

from lib import netntlmv2
from lib.test_helpers import kernel_charset, utf16le

# NetNTLMv2, see lib/netntlmv2.py. The NT hash is MD4 of the UTF-16LE password, which the two kernel
# families convert differently, see kernel_charset (); MD4 is pycryptodome's, because hashlib often
# has none.

CHARSET = kernel_charset()


def module_constraints():
  return [[0, 127], [0, 55], [0, 27], [0, 27], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, domain=None, srv_ch=None, cli_ch=None):
  nthash = MD4.new(utf16le(word, CHARSET)).digest()

  return netntlmv2.generate_hash(nthash, salt, domain, srv_ch, cli_ch)


def module_verify_hash(line):
  parsed = netntlmv2.parse(line)

  if parsed is None:
    return None

  user, domain, srv_ch, cli_ch, word = parsed

  try:
    return (module_generate_hash(word, user, None, domain, srv_ch, cli_ch), word)
  except ValueError:
    return None
