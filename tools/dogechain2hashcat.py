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
        # verify basic fields
        if ("pbkdf2_iterations" not in wallet) or ("payload" not in wallet) or ("salt" not in wallet):
            parser.error("Unsupported wallet format")
        # variant
        if ("cipher" not in wallet) or (wallet["cipher"].upper() == "AES-CBC"):
            variant = 0
        elif wallet["cipher"].upper() == "AES-GCM":
            variant = 1
        else:
            parser.error("Unsupported wallet cipher variant")
        # iterations
        iterations = wallet["pbkdf2_iterations"]
        # payload
        payload = b64decode(wallet["payload"])
        payload = payload[:240]  # payload length must be equal to 320
        payload = b64encode(payload)
        payload = payload.decode()
        # salt
        salt = wallet["salt"]
        # print
        print("$dogechain$" + "*".join([str(variant), str(iterations), payload, salt]))
    except IOError as e:
        parser.error(e.strerror.lower())
