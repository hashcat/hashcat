#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import netntlmv2
from lib.test_helpers import pack_hex

# NetNTLMv2 (NT): the password is the NT hash itself, in hex, see lib/netntlmv2.py. The perl verify
# packed the hex twice, once itself and once in generate; the python one packs it once.


def module_constraints():
  return [[32, 32], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, domain=None, srv_ch=None, cli_ch=None):
  return netntlmv2.generate_hash(pack_hex(word), salt or "", domain, srv_ch, cli_ch)


def module_verify_hash(line):
  parsed = netntlmv2.parse(line)

  if parsed is None:
    return None

  user, domain, srv_ch, cli_ch, word = parsed

  try:
    return (module_generate_hash(word, user, None, domain, srv_ch, cli_ch), word)
  except ValueError:
    return None
