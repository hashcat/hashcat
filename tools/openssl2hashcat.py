#!/usr/bin/env python3

# Author......: See docs/credits.txt
# License.....: MIT

# Extracts a hashcat -m 2300 hash from a file written by "openssl enc" with AES-CBC and the default
# EVP_BytesToKey key derivation, raw or base64 ("openssl enc -a"). The line is the one John the
# Ripper's openssl2john.py writes, without the leading file name. Files written with -pbkdf2 or -iter
# use a different key derivation and are not covered.
#
# The padding of the last block alone lets about one wrong password in 256 through, so give the
# expected plaintext with -p or a minimum share of printable ASCII with -a wherever possible.

import argparse
import base64
import binascii
import sys

CIPHERS = {"aes-256-cbc": 0, "aes-128-cbc": 1}
MDS     = {"md5": 0, "sha1": 1, "sha256": 2}


def process(path, cipher, md, plaintext, min_ascii):
  with open(path, "rb") as f:
    data = f.read()

  if data.startswith(b"Salted__") is False:
    try:
      data = base64.b64decode(b"".join(data.split()), validate=True)
    except (binascii.Error, ValueError):
      data = b""

  if data.startswith(b"Salted__") is False:
    sys.stderr.write("%s: not written by openssl enc with a salt\n" % path)
    return

  salt = data[8:16]
  ct   = data[16:]

  if (len(ct) == 0) or ((len(ct) % 16) != 0):
    sys.stderr.write("%s: the ciphertext is not a whole number of AES blocks\n" % path)
    return

  if plaintext is not None:
    check = "1$%s" % plaintext
  elif min_ascii is not None:
    check = "2$%d" % min_ascii
  else:
    check = "0"

  head = "$openssl$%d$%d$8$%s" % (cipher, md, salt.hex())

  if len(ct) == 16:
    sys.stdout.write("%s$%s$1$%s\n" % (head, ct.hex(), check))
    return

  # the first 256 bytes are enough to test a known plaintext or the share of ASCII

  first = ct[:256]

  sys.stdout.write("%s$%s$0$%d$%s$%s\n" % (head, ct[-32:].hex(), len(first), first.hex(), check))


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="openssl enc to hashcat -m 2300")

  parser.add_argument("-c", "--cipher", choices=CIPHERS.keys(), default="aes-256-cbc")
  parser.add_argument("-m", "--md", choices=MDS.keys(), default="sha256", help="the -md of openssl enc, sha256 since OpenSSL 1.1.0, md5 before")
  parser.add_argument("-p", "--plaintext", help="text the decrypted data is known to contain")
  parser.add_argument("-a", "--min-ascii", type=int, help="minimum share of printable ASCII in the decrypted data, in percent")
  parser.add_argument("files", nargs="+")

  args = parser.parse_args()

  if (args.plaintext is not None) and ((args.plaintext.find("\n") >= 0) or (args.plaintext.find("\r") >= 0) or (args.plaintext.find(":") >= 0) or (len(args.plaintext) > 255)):
    sys.stderr.write("the known plaintext must be one line of at most 255 characters without a colon\n")
    sys.exit(1)

  if (args.min_ascii is not None) and ((args.min_ascii < 1) or (args.min_ascii > 100)):
    sys.stderr.write("the ASCII share is a percentage from 1 to 100\n")
    sys.exit(1)

  for path in args.files:
    process(path, CIPHERS[args.cipher], MDS[args.md], args.plaintext, args.min_ascii)
