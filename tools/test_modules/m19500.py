#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_numeric_string

# Ruby on Rails Restful-Authentication: ten rounds of SHA-1 over the site key, the salt and the
# password joined by --.


def module_constraints():
  return [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, site_key=None):
  site_key = site_key or random_numeric_string(40)

  tail = b"--" + salt.encode() + b"--" + word + b"--" + site_key.encode()

  digest = hashlib.sha1(site_key.encode() + tail).hexdigest()

  for _ in range(9):
    digest = hashlib.sha1(digest.encode() + tail).hexdigest()

  return "%s:%s:%s" % (digest, salt, site_key)


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4:
    return None

  _, salt, site_key, word = parts

  return (module_generate_hash(word, salt.decode(), None, site_key.decode()), word)
