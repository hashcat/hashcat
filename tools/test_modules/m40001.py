#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import re

from lib.test_helpers import random_bytes, split_hash_salt_word, split_hash_word

# OSPFv2 and RIPv2 MD5 authentication (RFC 2328 D.4.3, RFC 2082): MD5 of the packet followed by
# the key, null padded or cut to 16 bytes. The packet is random bytes of the salt's length, and the
# line is written in the $netmd5$packet$digest form. A digest:packet line verifies as well.

NETMD5 = re.compile(r"^\$netmd5\$((?:[0-9a-fA-F]{2})+)\$([0-9a-fA-F]{32})$")
PLAIN  = re.compile(r"^([0-9a-fA-F]{32})$")
PACKET = re.compile(r"^((?:[0-9a-fA-F]{2})+)$")


def module_constraints():
  return [[0, 16], [1, 256], [-1, -1], [-1, -1], [-1, -1]]


def netmd5(word, packet):
  return hashlib.md5(packet + word[:16].ljust(16, b"\x00")).hexdigest()


def module_generate_hash(word, salt, iterations=None):
  packet = random_bytes(len(salt)) if salt else random_bytes(44)

  return "$netmd5$%s$%s" % (packet.hex(), netmd5(word, packet))


def module_verify_hash(line):
  if line.startswith(b"$netmd5$"):
    parts = split_hash_word(line)

    if parts is None:
      return None

    hash_in, word = parts

    m = NETMD5.match(hash_in)

    if m is None:
      return None

    packet = bytes.fromhex(m.group(1))

    return ("$netmd5$%s$%s" % (m.group(1), netmd5(word, packet)), word)

  parts = split_hash_salt_word(line)

  if parts is None:
    return None

  hash_in, packet_hex, word = parts

  if PLAIN.match(hash_in) is None or PACKET.match(packet_hex) is None:
    return None

  packet = bytes.fromhex(packet_hex)

  return ("%s:%s" % (netmd5(word, packet), packet_hex), word)
