#!/usr/bin/env python3

# Author......: See docs/credits.txt
# License.....: MIT

# Extracts a hashcat -m 2300 hash from a file written by "openssl enc" with AES-CBC and the default
# EVP_BytesToKey key derivation, raw or base64 ("openssl enc -a"). The line is the one John the
# Ripper's openssl2john.py writes, without the leading file name. Files written with -pbkdf2 or -iter
# use a different key derivation and are not covered.
#
# The padding of the last block alone lets about one wrong password in 255 through, and hash-mode
# 2300 refuses a line that checks nothing else. Give the expected plaintext with -p or a minimum
# share of printable ASCII with -a.

import argparse
import base64
import binascii
import math
import sys

CIPHERS = {"aes-256-cbc": 0, "aes-128-cbc": 1}
MDS     = {"md5": 0, "sha1": 1, "sha256": 2}

# the length of a known plaintext that hash-mode 2300 takes, in bytes

KPT_MIN = 5
KPT_MAX = 255


# The module counts and compares the known plaintext in bytes, so the line goes out as the bytes its
# length was counted in: UTF-8 whatever the encoding of the console, and an argument that is not
# valid UTF-8 keeps its own bytes.

def line_bytes(text):
  return text.encode("utf-8", "surrogateescape")


# OPENSSL_ENC_ASCII_MIN of src/modules/module_02300.c, computed rather than copied. It is the least
# number of printable bytes in a window of this size that keeps a wrong password under one in 2^32,
# together with the padding that lets one in 255 through. A random byte is printable with odds of 97
# in 256 (0x0a, 0x0d and 0x20 to 0x7e). 0 means that no count is enough.

def ascii_count_min(window):
  tail = 0
  need = 0

  for n in range(window, -1, -1):
    tail += math.comb(window, n) * (97 ** n) * (159 ** (window - n))

    if (tail << 32) >= (255 * (256 ** window)): break

    need = n

  return need


# the least -a that hash-mode 2300 takes for a file of this many bytes of ciphertext, or 0 if it
# takes none. The module judges a line by the data it carries less the 16 bytes the padding can
# strip, and a single block carries no data.

def ascii_pct_min(ct_len):
  window = 0

  if ct_len > 16: window = min(ct_len, 256) - 16

  need = ascii_count_min(window)

  if need == 0: return 0

  for pct in range(1, 101):
    if (((pct * window) + 99) // 100) >= need: return pct

  return 0


def process(path, cipher, md, plaintext, min_ascii):
  try:
    with open(path, "rb") as f:
      data = f.read()
  except OSError as e:
    sys.stderr.write("%s: %s\n" % (path, e.strerror))
    return False

  if data.startswith(b"Salted__") is False:
    try:
      data = base64.b64decode(b"".join(data.split()), validate=True)
    except (binascii.Error, ValueError):
      data = b""

  if data.startswith(b"Salted__") is False:
    sys.stderr.write("%s: not written by openssl enc with a salt\n" % path)
    return False

  salt = data[8:16]
  ct   = data[16:]

  if (len(ct) == 0) or ((len(ct) % 16) != 0):
    sys.stderr.write("%s: the ciphertext is not a whole number of AES blocks\n" % path)
    return False

  if plaintext is not None:
    check = "1$%s" % plaintext
  else:
    pct_min = ascii_pct_min(len(ct))

    if pct_min == 0:
      sys.stderr.write("%s: %d bytes of ciphertext are too few for -a, give the known plaintext with -p\n" % (path, len(ct)))
      return False

    if min_ascii < pct_min:
      sys.stderr.write("%s: hash-mode 2300 needs -a %d or more for %d bytes of ciphertext\n" % (path, pct_min, len(ct)))
      return False

    check = "2$%d" % min_ascii

  head = "$openssl$%d$%d$8$%s" % (cipher, md, salt.hex())

  if len(ct) == 16:
    sys.stdout.buffer.write(line_bytes("%s$%s$1$%s\n" % (head, ct.hex(), check)))
    return True

  # the first 256 bytes are enough to test a known plaintext or the share of ASCII

  first = ct[:256]

  sys.stdout.buffer.write(line_bytes("%s$%s$0$%d$%s$%s\n" % (head, ct[-32:].hex(), len(first), first.hex(), check)))

  return True


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="openssl enc to hashcat -m 2300")

  parser.add_argument("-c", "--cipher", choices=CIPHERS.keys(), default="aes-256-cbc")
  parser.add_argument("-m", "--md", choices=MDS.keys(), default="sha256", help="the -md of openssl enc, sha256 since OpenSSL 1.1.0, md5 before")
  parser.add_argument("-p", "--plaintext", help="text the decrypted data is known to contain")
  parser.add_argument("-a", "--min-ascii", type=int, help="minimum share of printable ASCII in the decrypted data, in percent")
  parser.add_argument("files", nargs="+")

  args = parser.parse_args()

  if (args.plaintext is None) and (args.min_ascii is None):
    sys.stderr.write("give the known plaintext with -p or a minimum share of printable ASCII with -a, hash-mode 2300 refuses a line that checks only the padding\n")
    sys.exit(1)

  if (args.plaintext is not None) and ((args.plaintext.find("\n") >= 0) or (args.plaintext.find("\r") >= 0) or (args.plaintext.find(":") >= 0) or (len(line_bytes(args.plaintext)) < KPT_MIN) or (len(line_bytes(args.plaintext)) > KPT_MAX)):
    sys.stderr.write("the known plaintext must be one line of %d to %d bytes without a colon\n" % (KPT_MIN, KPT_MAX))
    sys.exit(1)

  if (args.min_ascii is not None) and ((args.min_ascii < 1) or (args.min_ascii > 100)):
    sys.stderr.write("the ASCII share is a percentage from 1 to 100\n")
    sys.exit(1)

  rc = 0

  for path in args.files:
    if process(path, CIPHERS[args.cipher], MDS[args.md], args.plaintext, args.min_ascii) == False: rc = 1

  sys.exit(rc)
