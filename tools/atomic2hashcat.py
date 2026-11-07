#!/usr/bin/env python3
#
# Author......: @Banaanhangwagen
# License.....: MIT
#
# This script extracts a hash from the LevelDB-directory of Atomic Wallet (tested on v2.104.8).
#
# It opens LevelDB, extracts the "general_mnemonic" value, and converts it into a hashcat -m 2300 hash
# (openssl enc AES-CBC format) with the default values for Atomic Wallet.
# The openssl2hashcat.py has been merged into this script to automate this.
#
# Usage:
#     python atomic2hashcat.py /path/to/leveldb_dir
#
# Requires:
#     pip install plyvel
# (Use WSL or Linux - plyvel needs the system leveldb library installed
#  e.g. apt install libleveldb-dev / brew install leveldb)


import argparse
import base64
import binascii
import shutil
import sys
import tempfile

import plyvel

TARGET_KEY = b"general_mnemonic"

BANNER = r"""      _             _    ___ _            _            _
 __ _| |_ ___ _ __ (_)__|_  ) |_  __ _ __| |_  __ __ _| |_
/ _` |  _/ _ \ '  \| / _|/ /| ' \/ _` (_-< ' \/ _/ _` |  _|
\__,_|\__\___/_|_|_|_\__/___|_||_\__,_/__/_||_\__\__,_|\__|
"""

CIPHERS = {"aes-256-cbc": 0, "aes-128-cbc": 1}
MDS     = {"md5": 0, "sha1": 1, "sha256": 2}


def find_value(db):
    """Return (key, value) for the key containing general_mnemonic."""
    for key, val in db.iterator():
        if TARGET_KEY in key:
            return key, val


def process_data(data, cipher, md, plaintext, min_ascii) -> bool:
    """Process binary data expected to be openssl-encrypted (raw or base64)."""
    if not data.startswith(b"Salted__"):
        try:
            data = base64.b64decode(b"".join(data.split()), validate=True)
        except (binascii.Error, ValueError):
            data = b""

    if not data.startswith(b"Salted__"):
        sys.stderr.write("general_mnemonic: not written by openssl enc with a salt\n")
        return False

    salt = data[8:16]
    ct   = data[16:]

    if (len(ct) == 0) or ((len(ct) % 16) != 0):
        sys.stderr.write("general_mnemonic: the ciphertext is not a whole number of AES blocks\n")
        return False

    if plaintext is not None:
        check = f"1${plaintext}"
    else:
        check = f"2${min_ascii}"

    head = f"$openssl${cipher}${md}$8${salt.hex()}"

    if len(ct) == 16:
        print(f"{head}${ct.hex()}$1${check}")
        return True

    # the first 256 bytes are enough to test a known plaintext or the share of ASCII
    first = ct[:256]
    print(f"{head}${ct[-32:].hex()}$0${len(first)}${first.hex()}${check}")
    return True


def main():
    print(BANNER, file=sys.stderr)
    parser = argparse.ArgumentParser(
        description="Extract general_mnemonic from LevelDB and convert to hashcat -m 2300"
    )
    parser.add_argument("path", help="Path to the LevelDB directory")
    parser.add_argument("-c", "--cipher", choices=CIPHERS.keys(), default="aes-256-cbc")
    parser.add_argument("-m", "--md", choices=MDS.keys(), default="md5",
                        help="the -md of openssl enc (default: md5)")
    parser.add_argument("-p", "--plaintext", help="text the decrypted data is known to contain")
    parser.add_argument("-a", "--min-ascii", type=int, default=None,
                        help="minimum share of printable ASCII in the decrypted data, in percent (default: 100)")

    args = parser.parse_args()

    if args.plaintext is not None and args.min_ascii is not None:
        sys.stderr.write("warning: both -p and -a given; only -p is used\n")

    if args.plaintext is not None and (
        any(c in args.plaintext for c in "\n\r:")
        or len(args.plaintext) > 255
    ):
        parser.error("plaintext must be one line, max 255 chars, no colon")

    if args.min_ascii is not None and not 1 <= args.min_ascii <= 100:
        parser.error("the ASCII share is a percentage from 1 to 100")

    # Open a copy, not the original: opening a LevelDB triggers log compaction,
    # which modifies the wallet directory in place.
    found = None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.copytree(args.path, tmpdir, dirs_exist_ok=True)
            try:
                db = plyvel.DB(tmpdir, create_if_missing=False)
            except plyvel.Error as e:
                print(f"Failed to open LevelDB at {args.path!r}: {e}", file=sys.stderr)
                sys.exit(1)
            try:
                found = find_value(db)
            finally:
                db.close()
    except OSError as e:
        print(f"Failed to copy LevelDB from {args.path!r}: {e}", file=sys.stderr)
        sys.exit(1)

    if found is None:
        print("Key 'general_mnemonic' not found.", file=sys.stderr)
        sys.exit(2)

    _, value = found

    # the value may carry a small binary wrapper (e.g. a b"\x01" version/type byte)
    marker = value.find(b"Salted__")
    if marker != -1:
        raw = value[marker:]                 # raw openssl output -> use directly
    else:
        # no marker: expect base64 text, possibly after the wrapper byte(s)
        stripped = value.lstrip(b"\x00\x01\x02\x03")
        try:
            raw = base64.b64decode(b"".join(stripped.split()), validate=True)
        except (binascii.Error, ValueError):
            print("general_mnemonic: value is neither openssl output nor base64", file=sys.stderr)
            sys.exit(1)

    # effective value: -a defaults to 100 when not given
    min_ascii = args.min_ascii if args.min_ascii is not None else 100

    ok = process_data(
        raw,
        CIPHERS[args.cipher],
        MDS[args.md],
        args.plaintext,
        min_ascii,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
