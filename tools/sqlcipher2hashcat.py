#!/usr/bin/env python3
from base64 import b64encode
import sys

def usage():
  print('./sqlcipher2hashcat DATABASE_FILE')

def main():
  database = open(sys.argv[1], "rb").read(272)
  salt = database[:16]

  print('sqlcipherv4:256000:' + b64encode(salt).decode() + ':' + b64encode(database[16:272]).decode())
  
if __name__ == '__main__':
  if len(sys.argv < 2):
    usage()
   else:
    main()
