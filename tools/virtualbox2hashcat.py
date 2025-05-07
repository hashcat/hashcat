#!/usr/bin/env python3

#
# Author......: See docs/credits.txt
# License.....: MIT
#

import binascii
import struct
from argparse import ArgumentParser
from base64 import b64decode
from collections import namedtuple
from struct import Struct
from sys import stderr
from xml.dom import minidom

SIGNATURE = "$vbox$0$"

KEY_STORE_PROPERTY_NAME = "CRYPT/KeyStore"

KEY_STORE_STRUCT_FMT = "<4sxb32s32sI32sI32sI32sII64s"
KEY_STORE_STRUCT = Struct(KEY_STORE_STRUCT_FMT)

KeyStore = namedtuple(
    "KeyStore",
    [
        "FileHeader",
        "Version",
        "EVP_Algorithm",
        "PBKDF2_Hash",
        "Key_Length",
        "Final_Hash",
        "KL2_PBKDF2",
        "Salt2_PBKDF2",
        "Iteration2_PBKDF2",
        "Salt1_PBKDF2",
        "Iteration1_PBKDF2",
        "EVP_Length",
        "Enc_Password",
    ],
)


def print_warning(msg):
    print("Warning!", msg + ".", file=stderr)


def print_error(msg):
    print("Error!", msg + "!", file=stderr)
    exit(1)


def process_hard_disk(hard_disk):
    props = hard_disk.getElementsByTagName("Property")
    props = filter(lambda prop: prop.getAttribute("name") == KEY_STORE_PROPERTY_NAME, props)
    try:
        prop = next(props)  # assuming there is only one key store property per hard disk
        key_store = process_property(prop)
    except StopIteration:
        return None
    return key_store


def process_property(property):
    if not property.hasAttribute("value"):
        raise RuntimeWarning("Malformed key store property")
    key_store = property.getAttribute("value")
    try:
        key_store = b64decode(key_store)
        key_store = KEY_STORE_STRUCT.unpack(key_store)
        key_store = KeyStore(*key_store)
        int(key_store.Key_Length)
        return key_store
    except binascii.Error as error:
        raise RuntimeError("Malformed Base64 payload in key store property") from error
    except (ValueError, struct.error) as error:
        raise RuntimeError("Malformed payload in key store property") from error


if __name__ == "__main__":
    parser = ArgumentParser(description="virtualbox2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to VirtualBox file")

    args = parser.parse_args()

    try:
        document = minidom.parse(args.path)
    except IOError as error:
        print_error("Cannot read a file: " + error.strerror)

    hds = document.getElementsByTagName("HardDisk")
    if len(hds) == 0:
        print_error("No configured hard drives detected!")

    key_stores = []
    for hd in hds:
        try:
            key_store = process_hard_disk(hd)
            if key_store is not None:
                key_stores.append(key_store)
        except RuntimeWarning as warning:
            print_warning(warning)
        except RuntimeError as error:
            print_error(error)
    if len(key_stores) == 0:
        print_error("No valid key store found")
    for key_store in key_stores:
        key_length = int(key_store.Key_Length)
        hash = (
            SIGNATURE
            + str(key_store.Iteration1_PBKDF2)
            + "$"
            + key_store.Salt1_PBKDF2.hex()
            + "$"
            + str(key_length // 4)  # key_length in bits divided by sizeof(u32) to get the length in 32-bit words
            + "$"
            + key_store.Enc_Password[:key_length].hex()
            + "$"
            + str(key_store.Iteration2_PBKDF2)
            + "$"
            + key_store.Salt2_PBKDF2.hex()
            + "$"
            + key_store.Final_Hash.rstrip(b"\x00").hex()
        )
        print(hash)
