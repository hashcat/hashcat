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

def metamask_parser(file):
  try:
    f = open(file)

    j = json.load(f)

    if 'salt' not in j or 'iv' not in j or 'data' not in j:
      print("! Invalid vault format ...")
      parser.print_help()
      exit(1)

    print('$metamask$' + j['salt'] + '$' + j['iv'] + '$' + j['data'])
  except ValueError as e:
    parser.print_help()
    exit(1)

  exit(0)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="metamask2hashcat.py extraction tool")
  parser.add_argument('--vault', required=True, help='set metamask vault (json) file from path', type=str)

  args = parser.parse_args()
  if args.vault:
      metamask_parser(args.vault)
  else:
      parser.print_help()
      exit(1)

