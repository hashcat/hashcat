#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib import aix
from lib.test_helpers import split_hash_word, test_iteration_parameters

# Juniper/NetBSD sha1crypt: HMAC-SHA1 keyed with the password, iterated over "salt$sha1$iterations",
# written in the crypt alphabet. The 28th character is a random one the original tool adds; a line
# being verified keeps its own.


# ARTIFICIALLY_LOW_ITERATION_COUNT=true selects test.py's per-mode parameters.
ITERATION_PARAMETERS = test_iteration_parameters(40038)

NORMAL_ITERATIONS = 20000
DEFAULT_ITERATIONS = ITERATION_PARAMETERS.get('iterations', NORMAL_ITERATIONS)


def module_constraints():
  return [[0, 256], [8, 8], [0, 55], [8, 8], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, tail=None):
  iterations = DEFAULT_ITERATIONS if iterations is None else int(iterations)

  tmp = hmac.new(word, ("%s$sha1$%d" % (salt, iterations)).encode(), hashlib.sha1).digest()

  for _ in range(1, iterations):
    tmp = hmac.new(word, tmp, hashlib.sha1).digest()

  digest = "".join(aix.to64((tmp[i] << 16) | (tmp[i + 1] << 8) | tmp[i + 2], 4) for i in range(0, 18, 3))

  digest += aix.to64((tmp[18] << 16) | (tmp[19] << 8), 4)

  if tail is not None:
    digest = digest[:24] + tail[24:28]

  return "$sha1$%d$%s$%s" % (iterations, salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 5 or data[1] != "sha1":
    return None

  return (module_generate_hash(word, data[3], data[2], data[4]), word)
