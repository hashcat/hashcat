#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# PKZIP traditional PKWARE encryption (ZipCrypto) for the 172xx test modules.
#
# The key schedule is a byte exact port of the kernel macros in OpenCL/m172*-pure.cl: keys start at
# 0x12345678, 0x23456789 and 0x34567890, and a byte decrypts with ((key2 & 0xffff) | 3).
#
# Each file is written as a data_type_enum 2 block, full data: a 12 byte encryption header whose
# last byte is (crc >> 24) & 0xff, the value hashcat checks, then the encrypted file, stored for
# compression type 0 and raw deflate for type 8. Generating by encrypting the way hashcat decrypts
# means the right password passes every header check and CRC32 by construction.

import zlib

from lib.test_helpers import random_bytes, random_number


def _table():
  table = []

  for i in range(256):
    c = i

    for _ in range(8):
      c = (c >> 1) ^ (0xedb88320 if (c & 1) else 0)

    table.append(c)

  return table


TABLE = _table()


def _crc32(x, c):
  return ((x >> 8) ^ TABLE[(x ^ c) & 0xff]) & 0xffffffff


class ZipCrypto:
  def __init__(self, password):
    self.k = [0x12345678, 0x23456789, 0x34567890]

    for b in password:
      self.update(b)

  def update(self, c):
    self.k[0] = _crc32(self.k[0], c)
    self.k[1] = ((self.k[1] + (self.k[0] & 0xff)) * 0x08088405 + 1) & 0xffffffff
    self.k[2] = _crc32(self.k[2], (self.k[1] >> 24) & 0xff)

  def stream_byte(self):
    t = (self.k[2] & 0xffff) | 3

    return ((t * (t ^ 1)) >> 8) & 0xff

  def encrypt(self, data):
    out = bytearray()

    for p in data:
      out.append(p ^ self.stream_byte())
      self.update(p)

    return bytes(out)

  def decrypt(self, data):
    out = bytearray()

    for c in data:
      p = c ^ self.stream_byte()
      self.update(p)
      out.append(p)

    return bytes(out)


def _block(password, ctype):
  content = random_bytes(random_number(80, 320))

  crc = zlib.crc32(content)

  if ctype == 8:
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    stream = co.compress(content) + co.flush()
  else:
    stream = content

  header = bytearray(random_bytes(12))

  header[10] = (crc >> 16) & 0xff
  header[11] = (crc >> 24) & 0xff

  enc = ZipCrypto(password).encrypt(bytes(header) + stream)

  csum = (crc >> 16) & 0xffff

  # hashcat's encoder prints the lengths, the crc and the offsets with %x and no padding, so the
  # line has to match that or the recovered hash does not round trip

  return "2*0*%x*%x*%x*0*%x*%d*%x*%04x*%04x*%s" % (
    len(enc), len(content), crc, len(enc), ctype, len(enc), csum, csum, enc.hex())


def _container(mode):
  if mode == 17210:
    return [0]

  if mode == 17220:
    return [8] * random_number(2, 8)

  if mode == 17225:
    types = [8 if random_number(0, 1) else 0 for _ in range(random_number(3, 8))]

    # a genuine mix, whatever was drawn

    types[0] = 0
    types[1] = 8

    return types

  if mode == 17230:
    return [8] * random_number(3, 8)

  return [8]


def generate_hash(mode, password):
  types = _container(mode)

  return "$pkzip2$%d*1*%s*$/pkzip2$" % (len(types), "*".join(_block(password, t) for t in types))


def _parse(line):
  if not line.startswith("$pkzip2$"):
    raise ValueError("signature")

  core = line[len("$pkzip2$"):]

  if core.endswith("*$/pkzip2$"):
    core = core[:-len("*$/pkzip2$")]

  t = core.split("*")

  count = int(t[0])

  i = 2

  files = []

  for _ in range(count):
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

    files.append((ctype, crc, data))

  return files


def verify_hash(line):
  idx = line.rfind(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  try:
    files = _parse(hash_in)
  except (ValueError, IndexError):
    return None

  for ctype, crc, enc in files:
    dec = ZipCrypto(word).decrypt(enc)

    if dec[11] != ((crc >> 24) & 0xff):
      return None

    body = dec[12:]

    if ctype == 8:
      try:
        body = zlib.decompressobj(-15).decompress(body)
      except zlib.error:
        return None

    if zlib.crc32(body) != crc:
      return None

  return (hash_in, word)
