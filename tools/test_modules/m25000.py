#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib import snmpv3

# SNMPv3 HMAC-MD5-96/HMAC-SHA1-96: the line does not say which, so verify tries both. A new hash is
# always MD5, which is what the perl's int (rand (1)) + 1 always came to. See lib/snmpv3.py.


def module_constraints():
  return [[8, 256], [24, 3000], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  return snmpv3.generate_hash(0, hashlib.md5, word, salt)


def module_verify_hash(line):
  parsed = snmpv3.parse(0, line)

  if parsed is None:
    return None

  pkt_num, salt, engine_id, digest, word = parsed

  try:
    md5_hash = snmpv3.generate_hash(0, hashlib.md5, word, salt, pkt_num, engine_id)
    sha1_hash = snmpv3.generate_hash(0, hashlib.sha1, word, salt, pkt_num, engine_id)
  except ValueError:
    return None

  return (md5_hash if md5_hash.endswith("$" + digest) else sha1_hash, word)
