#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Based on "pyvmx-cracker" (https://github.com/axcheron/pyvmx-cracker) (MIT license)

# Author: Gabriele 'matrix' Gristina
# Version: 1.0
# Date: Tue 13 Jul 2021 01:29:23 PM CEST
# License: MIT

import argparse
from urllib.parse import unquote
from binascii import hexlify
import re
import base64

ks_re = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)'

ks_struct = {
    'password_hash': None,
    'password_cipher': None,
    'hash_round': None,
    'salt': None,
    'dict': None
}

def parse_keysafe(file):
    try:
        with open(file, 'r') as data:
            lines = data.readlines()
    except (OSError, IOError):
        sys.exit('[-] Cannot read from file ' + data)

    for line in lines:
        if 'encryption.keySafe' in line:
            keysafe = line

    keysafe = unquote(keysafe)

    match = re.match(ks_re, keysafe)
    if not match:
        msg = 'Unsupported format of the encryption.keySafe line:\n' + keysafe
        raise ValueError(msg)

    vmx_ks = ks_struct

    vmx_ks['password_hash'] = match.group(2)
    if vmx_ks['password_hash'] != 'PBKDF2-HMAC-SHA-1':
        msg = 'Unsupported password hash format: ' + vmx_ks['password_hash']
        raise ValueError(msg)

    vmx_ks['password_cipher'] = match.group(3)
    if vmx_ks['password_cipher'] != 'AES-256':
        msg = 'Unsupported cypher format: ' + vmx_ks['password_cypher']
        raise ValueError(msg)

    vmx_ks['hash_round'] = int(match.group(4))
    vmx_ks['salt'] = base64.b64decode(unquote(match.group(5)))
    vmx_ks['dict'] = base64.b64decode(match.group(7))[0:32]

    return vmx_ks

def pyvmx(vmx):
    keysafe = parse_keysafe(vmx)
    print("$vmx$0$" + str(keysafe['hash_round']) + "$" + hexlify(keysafe['salt']).decode() + "$" + hexlify(keysafe['dict']).decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vmwarevmx2hashcat extraction tool")
    parser.add_argument('--vmx', required=True, help='set vmware vmx file from path', type=str)

    args = parser.parse_args()
    if args.vmx:
        pyvmx(args.vmx)
    else:
        parser.print_help()
        exit(1)
