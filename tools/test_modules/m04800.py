#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import random_bytes

# iSCSI CHAP: md5(id.pass.challenge), the challenge and the id in hex after the digest. The salt
# is the two of them, "challenge:id", which is why the password takes 38 = 55 - 16 - 1.


def random_md5chap_salt():
  challenge = random_bytes(16).hex()

  return challenge + ":" + random_bytes(1).hex()


def module_constraints():
  return [[0, 256], [-1, -1], [0, 38], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  if not salt:
    salt = random_md5chap_salt()

  challenge, chap_id = salt.rsplit(":", 1)

  digest = hashlib.md5(bytes.fromhex(chap_id) + word + bytes.fromhex(challenge)).hexdigest()

  return "%s:%s" % (digest, salt)


def module_verify_hash(line):
  parts = line.split(b":", 3)

  if len(parts) != 4:
    return None

  _, challenge, chap_id, word = parts

  try:
    return (module_generate_hash(word, (challenge + b":" + chap_id).decode()), word)
  except ValueError:
    return None
