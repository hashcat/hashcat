#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Based on "pyvboxdie-cracker" (https://github.com/axcheron/pyvboxdie-cracker) (MIT license)

# Author: Gabriele 'matrix' Gristina
# Version: 1.0
# Date: Sat 17 Jul 2021 05:36:37 PM CEST
# License: MIT

import argparse
import xml.dom.minidom
import base64
from struct import *
from binascii import hexlify

keystore_struct = {
    'FileHeader': None,
    'Version':  None,
    'EVP_Algorithm': None,
    'PBKDF2_Hash': None,
    'Key_Length': None,
    'Final_Hash': None,
    'KL2_PBKDF2': None,
    'Salt2_PBKDF2' : None,
    'Iteration2_PBKDF2': None,
    'Salt1_PBKDF2': None,
    'Iteration1_PBKDF2': None,
    'EVP_Length': None,
    'Enc_Password': None
}

def parse_keystore(file):
    keystore = None

    try:
        fh_vbox = xml.dom.minidom.parse(file)
    except IOError:
        print('[-] Cannot open:', file)
        exit(1)

    hds = fh_vbox.getElementsByTagName("HardDisk")

    # TODO - Clean up & exceptions
    if len(hds) == 0:
        print('[-] No hard drive found')
        exit(1)
    else:
        for disk in hds:
            is_enc = disk.getElementsByTagName("Property")
            if is_enc:
                data = disk.getElementsByTagName("Property")[1]
                keystore = data.getAttribute("value")

    raw_ks = base64.decodebytes(keystore.encode())
    unpkt_ks = unpack('<4sxb32s32sI32sI32sI32sII64s', raw_ks)

    idx = 0
    ks = keystore_struct
    for key in ks.keys():
        ks[key] = unpkt_ks[idx]
        idx += 1

    return ks

def pyvboxdie(vbox):
    keystore = parse_keystore(vbox)
    print("$vbox$0$" + str(keystore['Iteration1_PBKDF2']) + "$" + hexlify(keystore['Salt1_PBKDF2']).decode() + "$" + str(int(keystore['Key_Length'] / 4)) + "$" + hexlify(keystore['Enc_Password'][0:keystore['Key_Length']]).decode() + "$" + str(keystore['Iteration2_PBKDF2']) + "$" + hexlify(keystore['Salt2_PBKDF2']).decode() + "$" + hexlify(keystore['Final_Hash'].rstrip(b'\x00')).decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="virtualbox2hashcat extraction tool")
    parser.add_argument('--vbox', required=True, help='set virtualbox vbox file from path', type=str)

    args = parser.parse_args()

    if args.vbox:
        pyvboxdie(args.vbox)
    else:
        parser.print_help()
        exit(1)
