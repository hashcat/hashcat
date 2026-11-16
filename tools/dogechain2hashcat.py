#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Write the hash line of a dogechain.info wallet backup for hash-mode 32500.
#
# The backup is a JSON object with the fields "payload", "salt" and "pbkdf2_iterations".
# The "cipher" field was added later, so an old backup may not carry it, and a missing
# field means AES-CBC, which is the cipher mode 32500 cracks.
#
# Two kinds of wallet cannot be cracked and are refused with a message. A "cipher" of
# AES-GCM is the newer wallet format, which has no hashcat mode yet, see
# https://github.com/hashcat/hashcat/issues/3868. And a payload that splits on ";" into
# equal blocks is RSA-wrapped transport data whose wrapping key existed only in the
# browser session, so it cannot be unwrapped offline.
#
# Mode 32500 reads exactly 240 payload bytes (320 base64 chars). A longer payload is cut
# down to that, which loses nothing: in AES-CBC the decryption of a block depends only on
# the blocks before it, and the mode checks the head of the decrypted plaintext.

import json

from argparse import ArgumentParser
from base64 import b64decode, b64encode

PAYLOAD_LEN = 240
SALT_LEN    = 16


def b64_field (parser, name, value):

  if isinstance (value, str) == False:
    parser.error ("Unsupported wallet format: invalid %s type" % name)

  try:
    raw = b64decode (value, validate = True)
  except ValueError:
    parser.error ("Unsupported wallet format: %s is not valid base64" % name)

  return raw


if __name__ == "__main__":

  parser = ArgumentParser (description = "dogechain2hashcat extraction tool")

  parser.add_argument ("path", type = str, help = "path to dogechain.info wallet backup file")

  args = parser.parse_args ()

  try:
    with open (args.path, encoding = "utf-8-sig") as file:
      wallet = json.load (file)
  except IOError as e:
    parser.error ("Failed to open wallet file: " + str (e))
  except json.JSONDecodeError:
    parser.error ("Unsupported wallet format: invalid JSON")
  except UnicodeDecodeError:
    parser.error ("Unsupported wallet format: invalid encoding")

  if isinstance (wallet, dict) == False:
    parser.error ("Unsupported wallet format: not a JSON object")

  # verify basic fields

  for field in ("payload", "salt", "pbkdf2_iterations"):
    if field not in wallet:
      parser.error ("Unsupported wallet format: missing %s field" % field)

  # cipher, a later addition to the wallet format, so an old backup may not carry it

  cipher = wallet.get ("cipher", "AES-CBC")

  if isinstance (cipher, str) == False:
    parser.error ("Unsupported wallet format: invalid cipher type")

  if cipher.upper () != "AES-CBC":
    parser.error ("Unsupported wallet cipher: %s (only AES-CBC is crackable, see hashcat issue #3868)" % cipher)

  # iterations

  iterations_str = str (wallet["pbkdf2_iterations"])

  if ((1 <= len (iterations_str) <= 10) == False) or (all (c in "0123456789" for c in iterations_str) == False):
    parser.error ("Unsupported wallet format: invalid pbkdf2_iterations format")

  if int (iterations_str) < 1:
    parser.error ("Unsupported wallet format: invalid pbkdf2_iterations value")

  # salt

  salt_raw = b64_field (parser, "salt", wallet["salt"])

  if len (salt_raw) != SALT_LEN:
    parser.error ("Unsupported wallet format: invalid salt length")

  # payload

  payload_str = wallet["payload"]

  if isinstance (payload_str, str) == False:
    parser.error ("Unsupported wallet format: invalid payload type")

  if ";" in payload_str:
    parser.error ("Unsupported wallet payload: RSA-wrapped transport data, the wrapping key existed only in the browser session and cannot be recovered offline")

  payload_raw = b64_field (parser, "payload", payload_str)

  if len (payload_raw) < PAYLOAD_LEN:
    parser.error ("Unsupported wallet payload: too short (%d decoded bytes, mode 32500 reads %d)" % (len (payload_raw), PAYLOAD_LEN))

  payload = b64encode (payload_raw[:PAYLOAD_LEN]).decode ()

  print ("$dogechain$0*%s*%s*%s" % (iterations_str, payload, wallet["salt"]))
