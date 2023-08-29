#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Gabriele 'matrix' Gristina
# Version: 2.1
# Date: Thu 28 Aug 2023 05:12:40 PM CEST
# License: MIT

# Extract metamask vault from browser and save to file, then you can use this tool
# reference: https://metamask.zendesk.com/hc/en-us/articles/360018766351-How-to-use-the-Vault-Decryptor-with-the-MetaMask-Vault-Data
# From version 2.0 works also for Metamask Mobile
# reference: https://github.com/3rdIteration/btcrecover/pull/346

import json
import argparse
import base64

def metamask_parser(file, shortdata):
  try:
    f = open(file)

    j = json.load(f)

    isMobile = False

    if 'engine' not in j:
      if 'salt' not in j or 'iv' not in j or 'data' not in j:
        print("! Invalid vault format ...")
        parser.print_help()
        exit(1)
    else:
      f.close()
      wallet_data = open(file, "rb").read().decode("utf-8","ignore").replace("\\","")

      # taken from https://github.com/3rdIteration/btcrecover/blob/master/btcrecover/btcrpass.py#L3096-L3103
      walletStartText = "vault"
      wallet_data_start = wallet_data.lower().find(walletStartText)
      wallet_data_trimmed = wallet_data[wallet_data_start:]
      wallet_data_start = wallet_data_trimmed.find("cipher")
      wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2:]
      wallet_data_end = wallet_data_trimmed.find("}")
      wallet_data = wallet_data_trimmed[:wallet_data_end + 1]
      wallet_json = json.loads(wallet_data)

      j = json.loads(wallet_data)

      if 'lib' in j and 'original' in j['lib']:
        isMobile = True
      else:
        print("! Invalid vault format ...")
        parser.print_help()
        exit(1)

    if isMobile is False:

      if((len(j['data']) > 3000) or shortdata):
        data_bin = base64.b64decode(j['data'])
        # TODO limit data to 16 bytes, we only check the first block of data, so we don't need more data.
        #  The use of smaller buffers should speedup the attack.
        #  Still the pbkdf 10k iter will be taking the most time by far probably.
        j['data'] = base64.b64encode(data_bin[0:64]).decode("ascii")

        print('$metamask-short$' + j['salt'] + '$' + j['iv'] + '$' + j['data'])
      else:
        print('$metamask$' + j['salt'] + '$' + j['iv'] + '$' + j['data'])

    else:

      # extract first 32 bytes of ciphertext for enhanced resistance to false-positives

      cipher_bin = base64.b64decode(j['cipher'])
      j['cipher'] = base64.b64encode(cipher_bin[:32]).decode("ascii")

      print('$metamaskMobile$' + j['salt'] + '$' + j['iv'] + '$' + j['cipher'])

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
