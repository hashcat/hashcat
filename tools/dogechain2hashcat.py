#!/usr/bin/env python3

#
# Author......: See docs/credits.txt
# License.....: MIT
#

import json
from argparse import ArgumentParser
from base64 import b64decode, b64encode


if __name__ == "__main__":
    # prepare parser and parse args
    parser = ArgumentParser(description="dogechain2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to dogechain wallet")
    args = parser.parse_args()

    try:
        # open wallet file
        with open(args.path) as file:
            wallet = json.load(file)
    except IOError as e:
        parser.error("Failed to open wallet file: " + str(e))
    except json.JSONDecodeError:
        parser.error("Unsupported wallet format: invalid JSON")
    except UnicodeDecodeError:
        parser.error("Unsupported wallet format: invalid encoding")

    # verify basic fields
    if "pbkdf2_iterations" not in wallet:
        parser.error("Unsupported wallet format: missing pbkdf2_iterations field")
    if "payload" not in wallet:
        parser.error("Unsupported wallet format: missing payload field")
    if "salt" not in wallet:
        parser.error("Unsupported wallet format: missing salt field")
    if "cipher" not in wallet:
        parser.error("Unsupported wallet format: missing cipher field")
    # type guards
    if not isinstance(wallet["cipher"], str):
        parser.error("Unsupported wallet format: invalid cipher type")
    if not isinstance(wallet["payload"], str):
        parser.error("Unsupported wallet format: invalid payload type")
    if not isinstance(wallet["salt"], str):
        parser.error("Unsupported wallet format: invalid salt type")
    # salt
    salt = wallet["salt"]
    if len(salt) != 24:  # module_32500.c requires exactly 24 base64 chars
        parser.error("Unsupported wallet format: invalid salt length")
    # iterations
    iterations_str = str(wallet["pbkdf2_iterations"])
    if (not (1 <= len(iterations_str) <= 10)) or (not all(c in "0123456789" for c in iterations_str)):
        parser.error("Unsupported wallet format: invalid pbkdf2_iterations format")
    # cipher
    cipher = wallet["cipher"].upper()
    if cipher == "AES-CBC":
        variant = "0"
    else:
        parser.error("Unsupported wallet cipher variant: " + cipher)
    # payload
    if ";" in wallet["payload"]:
        parser.error("Unsupported wallet payload: RSA-transport-wrapped (encrypted with an ephemeral browser-session key that is never stored, so it cannot be decrypted offline)")
    payload = b64decode(wallet["payload"])
    if len(payload) < 240:
        parser.error("Unsupported wallet payload: too short (expected at least 240 decoded bytes)")
    payload = payload[:240]  # module_32500.c requires exactly 240 bytes (320 base64 chars)
    payload = b64encode(payload)
    payload = payload.decode()
    # print
    print("$dogechain$" + "*".join([variant, iterations_str, payload, salt]))
