#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Gabriele 'matrix' Gristina
# Version: 1.0
# Date: Fri May  7 01:02:56 CEST 2021
# License: MIT

import argparse
import os.path
import sys

kern_type = -1
hash_mode = -1
hash_modes = [ 14511, 14512, 14513, 14521, 14522, 14523, 14531, 14532, 14533, 14541, 14542, 14543, 14551, 14552, 14553 ]

def validate_source(parser, arg):
  if not os.path.exists(arg):
    parser.error("! Invalid source argument: does not exist")
  else:
    return open(arg, 'rb')

def validate_keysize(parser, ks):
  if ks == '128':
    return 0
  elif ks == '192':
    return 1
  elif ks == '256':
    return 2
  else:
    parser.error("! Invalid key size selected ...")

def valid_hash_cipher(hash, cipher):
  if hash != 'sha1' and hash != 'sha256' and hash != 'sha512' and hash != 'ripemd160' and hash != 'whirlpool':
    print("! Invalid or not supported hash type")
    exit(1)

  if cipher != 'aes' and cipher != 'serpent' and cipher != 'twofish':
    print("! Invalid or not supported cipher")
    exit(1)

  if hash == 'sha1':
    if cipher == 'aes':
      return 0
    elif cipher == 'serpent':
      return 1
    else:
      return 2
  elif hash == 'sha256':
    if cipher == 'aes':
      return 3
    elif args.cipher == 'serpent':
      return 4
    else:
      return 5
  elif hash == 'sha512':
    if cipher == 'aes':
      return 6
    elif cipher == 'serpent':
      return 7
    else:
      return 8
  elif hash == 'ripemd160':
    if cipher == 'aes':
      return 9
    elif cipher == 'serpent':
      return 10
    else:
      return 11
  else: # whirlpool
    if cipher == 'aes':
      return 12
    elif cipher == 'serpent':
      return 13
    else:
      return 14

parser = argparse.ArgumentParser(description='cryptoloop2hashcat extraction tool')

parser.add_argument('--source', required=True, help='set cryptoloop disk/image from path', type=lambda src: validate_source(parser, src))
parser.add_argument('--hash', required=True, help='set hash type. Supported: sha1, sha256, sha512, ripemd160 or whirlpool.')
parser.add_argument('--cipher', required=True, help='set cipher type. Supported: aes, serpent or twofish.')
parser.add_argument('--keysize', required=True, help='set key size. Supported: 128, 192 or 256.', type=lambda ks: validate_keysize(parser, ks))

args = parser.parse_args()

kern_type = valid_hash_cipher(args.hash, args.cipher)
hash_mode = hash_modes[kern_type]
key_size = args.keysize

f = args.source
f.seek(1536)

if sys.version_info[0] == 3:
  ct = f.read(16).hex()
else:
  ct = f.read(16).encode('hex')

f.close()

print('$cryptoapi$' + str(kern_type) + '$' + str(key_size) + '$03000000000000000000000000000000$00000000000000000000000000000000$' + ct)
