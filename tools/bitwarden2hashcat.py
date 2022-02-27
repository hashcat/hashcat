"""Utility to extract Bitwarden data from Google Chrome / Firefox / Android local data"""

# Based on bitwarden2john.py https://github.com/willstruggle/john/blob/master/bitwarden2john.py

from dataclasses import dataclass
import os
import argparse
import string
import sys
import base64
import binascii
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        sys.stderr.write("Please install json module which is currently not installed.\n")
        sys.exit(-1)

try:
    import leveldb
except ImportError:
    sys.stderr.write("[WARNING] Please install the leveldb module for full functionality!\n")
    sys.exit(-1)
    
    
@dataclass
class BitwardenData:
    email: string
    enc_key: string
    key_hash: string
    iterations: int = 0


def process_xml_file(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    email = None
    enc_key = None

    for item in root:
        if item.tag == 'string':
            name = item.attrib['name']
            if name == "encKey":
                enc_key = item.text
            if name == "email":
                email = item.text
    return email, enc_key


def process_leveldb(path):
    db = leveldb.LevelDB(path, create_if_missing=False)

    for key, value in db.RangeIter():
        print(key.decode('ascii').strip('"') + " " + value.decode('ascii').strip('"'))

    data = BitwardenData(
        email = db.Get(b'userEmail')\
            .decode("utf-8")\
            .strip('"').rstrip('"'), 
        enc_key = db.Get(b'encKey')\
            .decode("ascii").strip('"').rstrip('"'),
        key_hash = db.Get(b'keyHash')\
            .decode("ascii").strip('"').rstrip('"'),
        # Usually 100000
        iterations = int(db.Get(b'kdfIterations').decode("ascii"))
    )
    
    print(data)

    return data


def process_file(filename):
    if "nngceckbap" in filename or os.path.isdir(filename):
        try:
            bitw_data = process_leveldb(filename)
            if not bitw_data.email or not bitw_data.enc_key:
                sys.stderr.write("[error] %s could not be parsed properly!\n" % filename)
                return
        except:
            traceback.print_exc()
            return
    else:
        with open(filename, "rb") as f:
            data = f.read()
        if filename.endswith(".xml") or data.startswith(b"<?xml"):
            try:
                email, enc_key = process_xml_file(filename)
                if not email or not enc_key:
                    sys.stderr.write("[error] %s could not be parsed properly!\n" % filename)
                    return
            except:
                traceback.print_exc()
                return
        else:
            try:
                data = json.loads(data)
                bitw_data = BitwardenData(
                    email = data["userEmail"],
                    enc_key = data["encKey"],
                    key_hash = data["keyHash"],
                    # Usually 100000
                    iterations = data["kdfIterations"]
                )
            except (valueerror, keyerror):
                traceback.print_exc()
                sys.stderr.write("Missing values, user is probably logged out.")
                return

    sys.stdout.write("%s: $bitwarden$2*%s*%s*%s\n" %
                     (os.path.basename(filename), bitw_data.iterations, base64.b64encode(bitw_data.email.encode("ascii")).decode("ascii"), bitw_data.key_hash))

    # iterations = 5000  # seems to be fixed in the design
    # email = bitw_data.email.lower()
    # iv_mix, blob = bitw_data.enc_key.split("|")
    # iv = iv_mix[2:]  # skip over "0."
    # iv = binascii.hexlify(base64.b64decode(iv)).decode("ascii")
    # blob = binascii.hexlify(base64.b64decode(blob)).decode("ascii")
    # sys.stdout.write("%s:$bitwarden$0*%s*%s*%s*%s\n" %
                    #  (os.path.basename(filename), iterations, email, iv, blob))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=str, nargs="+")
    args = parser.parse_args()
    
    print(args.path)

    # if len(sys.argv) < 2:
        # sys.stderr.write("Usage: %s <Bitwarden storage.js / com.x8bit.bitwarden_preferences.xml / Google Chrome's 'nngceckbap...' path>\n" %
                        #  sys.argv[0])
        # sys.exit(-1)

    for p in args.path:
        process_file(p)
