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

# The first deflated file of a hash is drawn far larger than the others, because what the decoder has
# to walk is the output window it owns: filling it, wrapping it and matching back through the wrap.
# A window is TINFL_LZ_DICT_SIZE, so 128 KB of output crosses it four times and nothing smaller
# crosses it at all. The content is a pool of chunks repeated at random, so it deflates to long back
# references and the block in the hash stays a fraction of what comes out of it. Only the first file
# gets it, so one hash walks both the wrapping path and the path that answers in a single call.

WINDOW_MIN = 128 * 1024
WINDOW_MAX = 192 * 1024

CHUNK_POOL = 256
CHUNK_MIN = 16
CHUNK_MAX = 96


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


def _window_content(size):
  pool = [random_bytes(random_number(CHUNK_MIN, CHUNK_MAX)) for _ in range(CHUNK_POOL)]

  out = bytearray()

  while len(out) < size:
    out += pool[random_number(0, CHUNK_POOL - 1)]

  return bytes(out[:size])


def _block(password, ctype, windowed):
  if windowed:
    content = _window_content(random_number(WINDOW_MIN, WINDOW_MAX))
  else:
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

  # a stored file goes into the hash as it stands, so giving one a window's worth of content would put
  # the hash past the 131072 bytes Linux allows in one argument

  first_deflated = types.index(8) if 8 in types else -1

  blocks = [_block(password, t, i == first_deflated) for i, t in enumerate(types)]

  return "$pkzip2$%d*1*%s*$/pkzip2$" % (len(types), "*".join(blocks))


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
