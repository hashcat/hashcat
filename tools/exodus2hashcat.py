#!/usr/bin/env python

# Author......: See docs/credits.txt
# License.....: MIT
# Target......: Exodus wallet extractor
# Example.....: exodus2hashcat.py <path to exodus seed seco file>

import binascii
import sys
import hashlib
from Crypto.Cipher import AES
import base64
import os.path

METADATA_LEN = 256
HEADER_LEN = 224
CRC_LEN = 32
LEN_BLOB_STORED = 4

if len(sys.argv) != 2 :
    print("Error, usage exodus2hashcat.py <path to exodus seed.seco file>")
    sys.exit(1)

if os.path.basename(sys.argv[1])!= 'seed.seco':
    print("Error, usage exodus2hashcat.py <path to exodus seed.seco file>")
    sys.exit(1)

with open(sys.argv[1],'rb') as fd:
    seedBuffer = fd.read()

#Basic check
if not seedBuffer[0:4].decode("utf8").startswith("SECO"):
    print("Not A SECO exodus header magic")
    sys.exit(1)

salt = seedBuffer[0x100:0x120]

n = int.from_bytes(seedBuffer[0x120:0x124],"big")
r = int.from_bytes(seedBuffer[0x124:0x128],"big")
p = int.from_bytes(seedBuffer[0x128:0x12c],"big")

#Basic check
if n!=16384 or r !=8 or p != 1:
    print("Warning,unexpected scrypt N,r,p values")

if os.path.getsize(sys.argv[1]) != METADATA_LEN + HEADER_LEN + CRC_LEN + LEN_BLOB_STORED+ int.from_bytes(seedBuffer[0x200:0x204],"big"):
    print(os.path.getsize(sys.argv[1]))
    print( METADATA_LEN + HEADER_LEN + int.from_bytes(seedBuffer[0x200:0x204],"big"))
    print("Error file size")
    sys.argv[1]

#Check integrity
m = hashlib.sha256()
m.update(seedBuffer[HEADER_LEN+CRC_LEN:])
if m.digest() != seedBuffer[HEADER_LEN:HEADER_LEN+CRC_LEN]:
    print("SECO file seems corrupted")
    sys.exit(1)

#Check aes-gcm string
cipher = seedBuffer[0x12c:0x138]
if binascii.hexlify(cipher) != b"6165732d3235362d67636d00":
    print("Error aes-256-gcm")
    sys.exit(1)

iv = seedBuffer[0x14c:0x158]
authTag = seedBuffer[0x158:0x168]
key = seedBuffer[0x168:0x188]

print("EXODUS:"+str(n)+":"+str(r)+":"+str(p)+":"+base64.b64encode(salt).decode("utf8")+":"+base64.b64encode(iv).decode("utf8")+":"+base64.b64encode(key).decode("utf8")+":"+base64.b64encode(authTag).decode("utf8"))
