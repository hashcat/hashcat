#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac

from lib.test_helpers import random_bytes, random_number

# WPA-PMKID-PBKDF2: the PMK is PBKDF2-HMAC-SHA1 of the passphrase over the ESSID, and the PMKID is
# the first half of HMAC-SHA1 of "PMK Name", the AP MAC and the station MAC.
#
# The perl module refused to verify, because hashcat prints a cracked PMKID with * rather than :
# between the fields. This one takes either, which is also what the python engine's round trip
# check needs.


def module_constraints():
  return [[8, 63], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, macap=None, macsta=None, essid=None):
  if macap is None:
    macap = random_bytes(6).hex()

  if macsta is None:
    macsta = random_bytes(6).hex()

  if essid is None:
    essid = random_bytes(random_number(0, 32) & 0x1e).hex()

  pmk = hashlib.pbkdf2_hmac("sha1", word, bytes.fromhex(essid), 4096, 32)

  pmkid = hmac.new(pmk, b"PMK Name" + bytes.fromhex(macap) + bytes.fromhex(macsta), hashlib.sha1).hexdigest()

  return "%s:%s:%s:%s" % (pmkid[:32], macap, macsta, essid)


def module_verify_hash(line):
  for sep in (b":", b"*"):
    data = line.split(sep, 3)

    if len(data) != 4:
      continue

    tail = data[3].split(b":", 1)

    if len(tail) != 2:
      continue

    _, macap, macsta = (d.decode(errors="replace") for d in data[:3])

    essid, word = tail[0].decode(errors="replace"), tail[1]

    try:
      new_hash = module_generate_hash(word, None, None, macap, macsta, essid)
    except ValueError:
      return None

    return (new_hash if sep == b":" else new_hash.replace(":", "*"), word)

  return None
