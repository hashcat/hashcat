#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# PKZIP traditional PKWARE / ZipCrypto. The key schedule is a byte exact port of the kernel
# macros in OpenCL/m172*-pure.cl: the three keys start at 0x12345678, 0x23456789 and
# 0x34567890, and the byte the plaintext is xored with comes out of key 2.
#
# Each file is emitted as a "full data" (data_type_enum 2) block: a 12 byte encryption header
# whose last byte is the top byte of the crc, which is the value hashcat checks, followed by
# the file itself, stored for compression type 0 and raw DEFLATE for 8, the whole thing under
# ZipCrypto. Generating by encrypting the way hashcat decrypts means a correct password
# reproduces every header check and every crc by construction.
#
# What separates the five modes is only the shape of the container, so that is what each of
# them passes in.

import re
import zlib

from .test_helpers import random_bytes, random_number

CONTENT_MIN = 80
CONTENT_MAX = 320

HEADER_LEN = 12

LINE = re.compile(r"\$pkzip2\$(.*)\*\$/pkzip2\$")


def _table():
  table = []

  for i in range(256):
    c = i

    for _ in range(8):
      c = (c >> 1) ^ 0xedb88320 if c & 1 else c >> 1

    table.append(c)

  return table


CRCTAB = _table()


def _c32(x, c):
  return (x >> 8) ^ CRCTAB[(x ^ c) & 0xff]


def _update(keys, c):
  keys[0] = _c32(keys[0], c)
  keys[1] = ((keys[1] + (keys[0] & 0xff)) * 0x08088405 + 1) & 0xffffffff
  keys[2] = _c32(keys[2], (keys[1] >> 24) & 0xff)


def _init(word):
  keys = [0x12345678, 0x23456789, 0x34567890]

  for c in word:
    _update(keys, c)

  return keys


def _stream_byte(keys):
  t = (keys[2] & 0xffff) | 3

  return ((t * (t ^ 1)) >> 8) & 0xff


def _encrypt(word, data):
  keys = _init(word)

  out = bytearray()

  for p in data:
    out.append(p ^ _stream_byte(keys))

    _update(keys, p)

  return bytes(out)


def _decrypt(word, data):
  keys = _init(word)

  out = bytearray()

  for c in data:
    p = c ^ _stream_byte(keys)

    _update(keys, p)

    out.append(p)

  return bytes(out)


def _deflate(data):
  # raw deflate, no zlib header, level 6 and memory level 8, which is what a zip writes

  z = zlib.compressobj(6, zlib.DEFLATED, -15, 8)

  return z.compress(data) + z.flush()


def _inflate(data):
  try:
    return zlib.decompressobj(-15).decompress(data)
  except zlib.error:
    return None


def _block(word, ctype):
  content = random_bytes(random_number(CONTENT_MIN, CONTENT_MAX))

  crc = zlib.crc32(content)

  stream = _deflate(content) if ctype == 8 else content

  header = bytearray(random_bytes(HEADER_LEN))

  header[10] = (crc >> 16) & 0xff
  header[11] = (crc >> 24) & 0xff

  enc = _encrypt(word, bytes(header) + stream)

  dlen = len(enc)
  csum = (crc >> 16) & 0xffff

  return "2*0*%x*%x*%x*0*%x*%d*%x*%04x*%04x*%s" % (dlen, len(content), crc, dlen, ctype, dlen,
                                                   csum, csum, enc.hex())


def deflate_many(minimum, maximum):
  return [8] * random_number(minimum, maximum)


def mixed(minimum, maximum):
  # both kinds have to be there, so the first two are pinned and the rest are drawn

  types = [(0, 8)[random_number(0, 1)] for _ in range(random_number(minimum, maximum))]

  types[0] = 0
  types[1] = 8

  return types


def generate_hash(types, word):
  return "$pkzip2$%d*1*%s*$/pkzip2$" % (len(types), "*".join(_block(word, t) for t in types))


def _accepts(word, line):
  # The line is checked by decrypting it rather than by generating it again, because every
  # block carries random content. A password is right when the last byte of the header is the
  # top byte of the crc and the file itself hashes to that crc.

  match = LINE.fullmatch(line)

  if match is None:
    return False

  t = match.group(1).split("*")

  i = 2

  try:
    for _ in range(int(t[0])):
      dtype = int(t[i])
      i += 2

      crc = 0

      if dtype > 1:
        crc = int(t[i + 2], 16)
        i += 5

      ctype = int(t[i])
      i += 4

      data = bytes.fromhex(t[i])
      i += 1

      dec = _decrypt(word, data)

      if len(dec) <= HEADER_LEN:
        return False

      if dec[11] != ((crc >> 24) & 0xff):
        return False

      body = dec[HEADER_LEN:]

      if ctype == 8:
        body = _inflate(body)

        if body is None:
          return False

      if zlib.crc32(body) != crc:
        return False
  except (IndexError, ValueError):
    return False

  return True


def verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    text = hash_in.decode("ascii")
  except UnicodeDecodeError:
    return None

  if _accepts(word, text) is False:
    return None

  return (text, word)
