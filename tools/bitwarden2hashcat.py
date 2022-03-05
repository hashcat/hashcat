"""Utility to extract Bitwarden hash for hashcat from Google Chrome / Firefox / Desktop local data"""

#
# Based on bitwarden2john.py https://github.com/willstruggle/john/blob/master/bitwarden2john.py
#
# Various data locations are documented here: https://bitwarden.com/help/data-storage/#on-your-local-machine
#
# Author: https://github.com/Greexter
# License: MIT
#

import os
import argparse
import sys
import base64
import traceback

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        print("Please install json module which is currently not installed.\n", file=sys.stderr)
        sys.exit(-1)


def process_sqlite(path):
    try:
        import snappy
    except ImportError:
        print("Please install python-snappy module.\n", file=sys.stderr)
        sys.exit(-1)
    try:
        import sqlite3
    except ImportError:
        print("Please install sqlite3 module.\n", file=sys.stderr)
        sys.exit(-1)

    conn = sqlite3.connect(path)
    cur = conn.cursor()
    data = cur.execute('SELECT * FROM object_data')
    fetched = data.fetchall()

    # uses undocumented nonstandard data format
    # probably can break in the future
    dataValue = snappy.decompress(fetched[0][4])

    key_hash = dataValue.split(b"keyHash")[1][9:53].decode()
    email = dataValue.split(b"email")[1][11:].split(b'\x00')[0].decode()
    iterations = int.from_bytes(dataValue.split(b"kdfIterations")[1][3:7], byteorder="little")
    
    return email, key_hash, iterations


def process_leveldb(path):
    try:
        import leveldb
    except ImportError:
        print("[WARNING] Please install the leveldb module for full functionality!\n", file=sys.stderr)
        return

    db = leveldb.LevelDB(path, create_if_missing=False)

    try:
        active = db.Get(b'activeUserId').decode().strip('"')
        data = db.Get(active.encode())
        return process_json(data)
    except(KeyError):
        # support for older Bitwarden versions (before account switch implementation)
        # data is stored in different format
        print("Failed to exctract data, trying old format.", file=sys.stderr)
        email = db.Get(b'userEmail')\
            .decode("utf-8")\
            .strip('"').rstrip('"')
        key_hash = db.Get(b'keyHash')\
            .decode("ascii").strip('"').rstrip('"')
        iterations = int(db.Get(b'kdfIterations').decode("ascii"))

    return email, key_hash, iterations


def process_json(data):
    data = json.loads(data)
    try:
        profile = data["profile"]
        email = profile["email"]
        iterations = profile["kdfIterations"]
        hash = profile["keyHash"]
    except(KeyError):
        print("Failed to exctract data, trying old format.", file=sys.stderr)
        email = data["rememberedEmail"]
        hash = data["keyHash"]
        iterations = data["kdfIterations"]

    return email, hash, iterations


def process_file(filename, legacy = False):
    try:
        if os.path.isdir(filename):
            # Chromium based
            email, key_hash, iterations = process_leveldb(filename)
        elif filename.endswith(".sqlite"):
            # Firefox
            email, key_hash, iterations = process_sqlite(filename)
        elif filename.endswith(".json"):
            # json - Desktop 
            with open(filename, "rb") as f:
                data = f.read()
                email, key_hash, iterations = process_leveldb(data)
        else:
            print("Unknown storage. Don't know how to extract data.", file=sys.stderr)
            sys.exit(-1)

    except (ValueError, KeyError):
        traceback.print_exc()
        print("Missing values, user is probably logged out.", file=sys.stderr)
        return
    except:
        traceback.print_exc()
        return

    if not email or not key_hash or not iterations:
        print("[error] %s could not be parsed properly!\nUser is probably logged out." % filename, file=sys.stderr)
        sys.exit(-1)

    iterations2 = 1 if legacy else 2

    print(f"$bitwarden$2*%d*%d*%s*%s\n" %
        (iterations, iterations2, base64.b64encode(email.encode("ascii")).decode("ascii"), key_hash))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", type=str, nargs="+")
    parser.add_argument("--legacy", action="store_true", help="Used for older versions of Bitwarden (before static iteration count had been changed).")

    args = parser.parse_args()

    for p in args.paths:
        process_file(p, args.legacy)
