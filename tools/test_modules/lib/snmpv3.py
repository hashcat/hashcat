#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SNMPv3 USM for the 25xxx and 26xxx test modules: the key is the digest of the password repeated to
# one megabyte, localised with the engine id, and the hash is the first 12 bytes of HMAC over the
# message.
#
# The perl drew the packet number with its own rand (), which no seed reaches; here it comes from
# lib/test_helpers.py like every other draw.

import hmac

from lib.test_helpers import random_hex_string, random_number


def localized_key(algo, word, engine_id):
  key = algo((word * (1048576 // len(word) + 1))[:1048576]).hexdigest()

  return algo(bytes.fromhex(key + engine_id + key)).digest()


def generate_hash(tag, algo, word, salt, pkt_num=None, engine_id=None, digest_len=24, engine_pad=0, print_padded=False):
  # digest_len is how many hex characters of the HMAC the line keeps; engine_pad zero pads the
  # engine id to that many hex characters for the key, and for the line as well with print_padded

  if pkt_num is None:
    pkt_num = random_number(0, 99999999)

  if engine_id is None:
    engine_id = random_hex_string(26)

  if len(salt) % 2 == 1:
    salt += "8"

  padded = engine_id + "0" * max(0, engine_pad - len(engine_id))

  key = localized_key(algo, word, padded)

  if print_padded:
    engine_id = padded

  digest = hmac.new(key, bytes.fromhex(salt), algo).hexdigest()[:digest_len]

  return "$SNMPv3$%d$%s$%s$%s$%s" % (tag, pkt_num, salt, engine_id, digest)


def parse(tag, line):
  # (pkt_num, salt, engine_id, digest, word) out of "$SNMPv3$tag$...:word"

  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if not word or not hash_in.startswith("$SNMPv3$%d$" % tag):
    return None

  data = hash_in.split("$")

  if len(data) < 7:
    return None

  return (data[3], data[4], data[5], data[6], word)


def verify_hash(tag, algo, line, digest_len=24, engine_pad=0, print_padded=False):
  parsed = parse(tag, line)

  if parsed is None:
    return None

  pkt_num, salt, engine_id, _, word = parsed

  try:
    return (generate_hash(tag, algo, word, salt, pkt_num, engine_id, digest_len, engine_pad, print_padded), word)
  except ValueError:
    return None
