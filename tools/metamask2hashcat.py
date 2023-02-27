#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Gabriele 'matrix' Gristina
# Version: 1.0
# Date: Thu 12 Aug 2021 06:44:14 PM CEST
# License: MIT

# Extract metamask vault from browser and save to file, then you can use this tool
# reference: https://metamask.zendesk.com/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data

import json
import argparse
import base64

def metamask_parser(file, shortdata):
  try:
    f = open(file)

    j = json.load(f)

    if 'salt' not in j or 'iv' not in j or 'data' not in j:
      print("! Invalid vault format ...")
      parser.print_help()
      exit(1)

    if((len(j['data']) > 3000) or shortdata):
      data_bin = base64.b64decode(j['data'])
      # TODO limit data to 16 bytes, we only check the first block of data, so we don't need more data.
      #  The use of smaller buffers should speedup the attack.
      #  Still the pbkdf 10k iter will be taking the most time by far probably.
      j['data'] = base64.b64encode(data_bin[0:64]).decode("ascii")

      print('$metamask-short$' + j['salt'] + '$' + j['iv'] + '$' + j['data'])
    else:
      print('$metamask$' + j['salt'] + '$' + j['iv'] + '$' + j['data'])
  except ValueError as e:
    parser.print_help()
    exit(1)

  exit(0)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="metamask2hashcat.py extraction tool")
  parser.add_argument('--vault', required=True, help='set metamask vault (json) file from path', type=str)
  parser.add_argument('--shortdata', help='force short data, can only be used with m26610, ', action='store_true')

  args = parser.parse_args()

  if args.vault:
      metamask_parser(args.vault, args.shortdata)
  else:
      parser.print_help()
      exit(1)

