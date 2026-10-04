#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# SAP CODVN B (BCODE) and CODVN F/G (PASSCODE) for the 77xx and 78xx test modules.

import hashlib

TRANSCODE = (
  b"\xff" * 32 +
  b"\x3f\x40\x41\x50\x43\x44\x45\x4b\x47\x48\x4d\x4e\x54\x51\x53\x46"
  b"\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x56\x55\x5c\x49\x5d\x4a"
  b"\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x58\x5b\x59\xff\x52"
  b"\x4c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x57\x5e\x5a\x4f\xff" +
  b"\xff" * 128
)

BCODE = (
  b"\x14\x77\xf3\xd4\xbb\x71\x23\xd0\x03\xff\x47\x93\x55\xaa\x66\x91"
  b"\xf2\x88\x6b\x99\xbf\xcb\x32\x1a\x19\xd9\xa7\x82\x22\x49\xa2\x51"
  b"\xe2\xb7\x33\x71\x8b\x9f\x5d\x01\x44\x70\xae\x11\xef\x28\xf0\x0d"
)

MAGIC = (
  b"\x91\xac\x51\x14\x9f\x67\x54\x43\x24\xe7\x3b\xe0\x28\x74\x7b\xc2"
  b"\x86\x33\x13\xeb\x5a\x4f\xcb\x5c\x08\x0a\x73\x37\x0e\x5d\x1c\x2f"
  b"\x33\x8f\xe6\xe5\xf8\x9b\xae\xdd\x16\xf2\x4b\x8d\x2c\xe1\xd4\xdc"
  b"\xb0\xcb\xdf\x9d\xd4\x70\x6d\x17\xf9\x4d\x42\x3f\x9b\x1b\x11\x94"
  b"\x9f\x5b\xc1\x9b\x06\x05\x9d\x03\x9d\x5e\x13\x8a\x1e\x9a\x6a\xe8"
  b"\xd9\x7c\x14\x17\x58\xc7\x2a\xf6\xa1\x99\x63\x0a\xd7\xfd\x70\xc3"
  b"\xf6\x5e\x74\x13\x03\xc9\x0b\x04\x26\x98\xf7\x26\x8a\x92\x93\x25"
  b"\xb0\xa2\x0d\x23\xed\x63\x79\x6d\x13\x32\xfa\x3c\x35\x02\x9a\xa3"
  b"\xb3\xdd\x8e\x0a\x24\xbf\x51\xc3\x7c\xcd\x55\x9f\x37\xaf\x94\x4c"
  b"\x29\x08\x52\x82\xb2\x3b\x4e\x37\x9f\x17\x07\x91\x11\x3b\xfd\xcd"
)


def _transcode(data):
  return bytes(TRANSCODE[c] for c in data)


def _waldorf(digest, w, s):
  sum20 = ((digest[0] & 3) + (digest[1] & 3) + (digest[2] & 3) + (digest[3] & 3) + (digest[5] & 3)) | 0x20

  out = {}

  i1 = i2 = i3 = 0

  while i2 < sum20:
    if i1 < len(w):
      if digest[15 - i1] & 1:
        out[i2] = BCODE[48 - 1 - i1]
        i2 += 1

      out[i2] = w[i1]
      i1 += 1
      i2 += 1

    if i3 < len(s):
      out[i2] = s[i3]
      i2 += 1
      i3 += 1

    out[i2] = BCODE[i2 - i1 - i3]

    i2 += 2

  return bytes(out.get(i, 0) for i in range(sum20))


def bcode(word, salt):
  # perl's uc () on a byte string folds ASCII only, and so does bytes.upper ()

  word_t = _transcode(word.upper())
  salt_t = _transcode(salt.upper())

  digest = hashlib.md5(_waldorf(hashlib.md5(word_t + salt_t).digest(), word_t, salt_t)).digest()

  a, b, c, d = (int.from_bytes(digest[i:i + 4], "big") for i in range(0, 16, 4))

  return (a ^ c, b ^ d)


def passcode(word, salt):
  salt = salt.upper()

  digest = hashlib.sha1(word + salt).digest()

  length = 0x20 + sum(digest[i] % 6 for i in range(10))
  offset = sum(digest[i] % 8 for i in range(10, 20))

  return hashlib.sha1(word + MAGIC[offset:offset + length] + salt).hexdigest().upper()


def split_line(line):
  # "salt$hash:word", the word empty if the line ends at the colon

  idx = line.find(b":")

  if idx < 1:
    return None

  fields = line[:idx].split(b"$")

  if len(fields) != 2:
    return None

  return (fields[0], line[idx + 1:].split(b":")[0])
