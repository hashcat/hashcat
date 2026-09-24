#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_bytes, pack_hex

# WPA-PMKID-PMK: identical to mode 16800 except the candidate is the 32 byte PMK itself (64 hex
# chars), so there is no PBKDF2 and no ESSID. The PMKID is the first half of HMAC-SHA1 of
# "PMK Name", the AP MAC and the station MAC. The PMK is packed from the candidate the way mode
# 22001 does it, which is how hashcat reads it.
#
# hashcat may print a cracked PMKID with * rather than : between the fields, so verify takes either.


def module_constraints():
  return [[64, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, macap=None, macsta=None):
  if macap is None:
    macap = random_bytes(6).hex()
  if macsta is None:
    macsta = random_bytes(6).hex()

  pmk = pack_hex(word)

  pmkid = hmac.new(pmk, b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta), hashlib.sha1).hexdigest()

  return "%s:%s:%s" % (pmkid[:32], macap, macsta)


def module_verify_hash(line):
  for sep in (b":", b"*"):
    head = line.split(sep, 2)

    if len(head) != 3:
      continue

    # the station MAC and the word are split by the first ':' left, whatever separated the hash
    tail = head[2].split(b":", 1)

    if len(tail) != 2:
      continue

    macap  = head[1].decode(errors="replace")
    macsta = tail[0].decode(errors="replace")
    word   = tail[1]

    try:
      new_hash = module_generate_hash(word, None, macap, macsta)
    except ValueError:
      return None

    return (new_hash if sep == b":" else new_hash.replace(":", "*"), word)

  return None
