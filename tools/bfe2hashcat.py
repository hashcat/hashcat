#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

#
# Extracts the hash from files encrypted with bcrypt, the Blowfish based file
# encryption utility from https://bcrypt.sourceforge.net/ (files ending in .bfe,
# not to be confused with the bcrypt password hash).
#
# File layout:
#
#   byte 0        endian tag: 0x54 file written on a little-endian machine,
#                             0x45 big-endian
#   byte 1        compression flag: 1 means the data is zlib compressed and the
#                 last 4 bytes of the file carry the uncompressed size in clear
#   bytes 2..n    Blowfish encrypted payload: data, then the 56 byte key the
#                 data was encrypted with, then zero padding to a multiple of 8
#
# The key check needs only the last two encrypted blocks: decrypted, they hold
# the end of the 56 byte key plus up to 7 padding zero bytes.
#
# Hash format: $bfe$endian$comp$ct
#
#   endian  0 if the file was written on a little-endian machine, else 1
#   comp    compression flag byte
#   ct      the last 16 bytes of the encrypted payload, hex encoded
#

import sys


def extract(path):
  try:
    f = open(path, "rb")
  except IOError as e:
    sys.stderr.write("%s: %s\n" % (path, e))
    return None

  with f:
    head = f.read(2)

    if len(head) < 2:
      sys.stderr.write("%s: file too short to be a .bfe file\n" % path)
      return None

    tag = head[0]
    comp = head[1]

    if tag == 0x54:
      endian = 0
    elif tag == 0x45:
      endian = 1
    else:
      sys.stderr.write("%s: invalid endian tag 0x%02x, not a .bfe file\n" % (path, tag))
      return None

    if comp not in (0, 1):
      sys.stderr.write("%s: invalid compression flag %d\n" % (path, comp))
      return None

    f.seek(0, 2)
    size = f.tell()

    end = size - (4 if comp == 1 else 0)

    enc_len = end - 2

    if enc_len < 16 or (enc_len % 8) != 0:
      sys.stderr.write("%s: invalid encrypted payload length %d\n" % (path, enc_len))
      return None

    f.seek(end - 16)
    ct = f.read(16)

    if len(ct) < 16:
      sys.stderr.write("%s: file too short to be a .bfe file\n" % path)
      return None

    return "$bfe$%d$%d$%s" % (endian, comp, ct.hex())


def main():
  if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s file.bfe ...\n" % sys.argv[0])
    sys.exit(1)

  rc = 0

  for path in sys.argv[1:]:
    h = extract(path)

    if h is None:
      rc = 1
    else:
      print(h)

  sys.exit(rc)


if __name__ == "__main__":
  main()
