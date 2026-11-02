#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import lzma
import struct
import zlib

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib.test_helpers import random_bytes, random_number, random_string, kernel_charset

# 7-Zip. The AES-256 key is one SHA-256 over 2^num_cycle_power copies of the UTF-16LE password each
# followed by an 8 byte little endian counter. The (zero padded) salt is the CBC IV. Generate
# encrypts a random buffer with Crypt::CBC standard (PKCS7) padding and stores its CRC32; verify
# decrypts, truncates to unpack_size and recomputes the CRC.
#
# A compressed line carries the data type, the length of the first file for the CRC and the coder
# attributes, and when a filter ran before the compressor, its attributes as one more field. The
# lower 4 bits of the data type name the compressor, the upper 4 bits the filter, the same way
# 7z2hashcat writes them. Its CRC covers the first crc_len bytes after decompressing and filtering.

CODERS = {1: lzma.FILTER_LZMA1, 2: lzma.FILTER_LZMA2}

FILTERS = {
  1: lzma.FILTER_X86,
  3: lzma.FILTER_POWERPC,
  4: lzma.FILTER_IA64,
  5: lzma.FILTER_ARM,
  6: lzma.FILTER_ARMTHUMB,
  7: lzma.FILTER_SPARC,
  9: lzma.FILTER_DELTA,
}

# Every filter is drawn with LZMA2, and x86 also with LZMA1, so both coders run with a filter. 0 is
# the stored data this module generated before.

DATA_TYPES = [0, 1, 2, 0x11, 0x12, 0x32, 0x42, 0x52, 0x62, 0x72, 0x92]

# A few instructions each branch converter rewrites, so the filter changes the data rather than
# passing random bytes through untouched: an x86 call, a PowerPC bl, an IA64 bundle whose third slot
# holds a branch, an ARM bl, a Thumb bl pair and a SPARC call.

BRANCHES = {
  1: b"\xe8\x10\x20\x30\x00",
  3: b"\x48\x00\x10\x01",
  4: b"\x10" + b"\x00" * 14 + b"\x50",
  5: b"\x10\x20\x30\xeb",
  6: b"\x10\xf0\x20\xf8",
  7: b"\x40\x00\x10\x20",
}


def module_constraints():
  return [[0, 256], [0, 16], [0, 20], [0, 16], [-1, -1]]


def _derive_key(word, num_cycle_power):
  word_utf16le = word.decode(kernel_charset(), errors="replace").encode("utf-16-le")

  rounds = 1 << num_cycle_power

  ctx = hashlib.sha256()

  for i in range(rounds):
    ctx.update(word_utf16le + struct.pack("<Q", i))

  return ctx.digest()


def _filter_chain(data_type, coder_props, filter_props):
  chain = []

  pre = data_type >> 4

  if pre != 0:
    chain.append(lzma._decode_filter_properties(FILTERS[pre], filter_props))

  chain.append(lzma._decode_filter_properties(CODERS[data_type & 0x0f], coder_props))

  return chain


def _plain_data(data_type):
  # The first file is 16 * k + 2 bytes long, so a branch placed 2 bytes before its end sits on the
  # alignment every filter needs and crosses into whatever follows.

  first = bytearray(random_bytes(16 * random_number(4, 16) + 2))

  branch = BRANCHES.get(data_type >> 4, b"")

  if len(branch) > 0:
    # every 32 bytes, which keeps an IA64 bundle on its 16 byte boundary

    for offset in range(0, len(first) - len(branch), 32):
      first[offset:offset + len(branch)] = branch

  # Half the time the folder holds a second file, and a branch then crosses from the first into it.
  # The CRC covers the first file only, and the filter converts that branch the way the encoder did
  # only when it is given the bytes after the first file.

  if random_number(0, 1) == 0:
    return bytes(first), len(first)

  data = first + bytearray(random_bytes(random_number(16, 64)))

  if len(branch) > 0:
    data[len(first) - 2:len(first) - 2 + len(branch)] = branch

  return bytes(data), len(first)


def _compress(data_type, data):
  chain = []

  pre = data_type >> 4

  if pre == 9:
    chain.append({"id": lzma.FILTER_DELTA, "dist": random_number(1, 256)})
  elif pre != 0:
    chain.append({"id": FILTERS[pre]})

  chain.append({"id": CODERS[data_type & 0x0f], "dict_size": 1 << 16})

  packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=chain)

  coder_props  = lzma._encode_filter_properties(chain[-1])
  filter_props = lzma._encode_filter_properties(chain[0]) if pre != 0 else b""

  return packed, coder_props, filter_props


def _compressed_crc(key, salt_buf, data_buf, data_type, crc_len, coder_props, filter_props):
  decrypted = AES.new(key, AES.MODE_CBC, salt_buf).decrypt(data_buf)

  # a wrong password decrypts to noise, which the decoder either refuses or turns into the wrong CRC

  try:
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=_filter_chain(data_type, coder_props, filter_props))

    plain = decompressor.decompress(decrypted, max_length=crc_len)
  except lzma.LZMAError:
    return 0

  if len(plain) < crc_len:
    return 0

  return zlib.crc32(plain) & 0xffffffff


def module_generate_hash(word, salt, iterations=None, seven_zip_salt_len=None,
                         seven_zip_salt_buf=None, salt_len=None, data_len=None,
                         unpack_size=None, data_buf=None, data_type=None,
                         crc_len=None, coder_props=None, filter_props=None):
  validation_only = seven_zip_salt_len is not None

  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if validation_only:
    num_cycle_power    = int(iterations)
    seven_zip_salt_len = int(seven_zip_salt_len)
    salt_len           = int(salt_len)
    data_len           = int(data_len)
    unpack_size        = int(unpack_size)
    data_type          = int(data_type)
  else:
    num_cycle_power    = 14
    seven_zip_salt_len = 0
    seven_zip_salt_buf = ""
    salt_len           = len(salt)
    data_type          = DATA_TYPES[random_number(0, len(DATA_TYPES) - 1)]

  key = _derive_key(word, num_cycle_power)

  salt_buf = salt

  if len(salt_buf) < 16:
    salt_buf = salt_buf + b"\x00" * (16 - len(salt_buf))

  if data_type == 0:
    if validation_only:
      decrypted_data = AES.new(key, AES.MODE_CBC, salt_buf).decrypt(data_buf)
      decrypted_data = decrypted_data[0:unpack_size]

      hash_buf = zlib.crc32(decrypted_data) & 0xffffffff
    else:
      unpack_size = random_number(1, 32 + 1)
      data_buf    = random_string(unpack_size).encode("latin-1")

      hash_buf = zlib.crc32(data_buf) & 0xffffffff

      data_buf = AES.new(key, AES.MODE_CBC, salt_buf).encrypt(pad(data_buf, 16))
      data_len = len(data_buf)

    return "$7z$%d$%d$%d$%s$%d$%s$%d$%d$%d$%s" % (
      data_type, num_cycle_power, seven_zip_salt_len, seven_zip_salt_buf, salt_len,
      salt_buf.hex(), hash_buf, data_len, unpack_size, data_buf.hex())

  # For compressed data unpack_size is the length of the packed stream and crc_len the length of the
  # data the CRC covers. 7-Zip pads the packed stream to the AES block size before it encrypts it.

  if validation_only:
    crc_len = int(crc_len)

    hash_buf = _compressed_crc(key, salt_buf, data_buf, data_type, crc_len, coder_props, filter_props)
  else:
    plain, crc_len = _plain_data(data_type)

    packed, coder_props, filter_props = _compress(data_type, plain)

    unpack_size = len(packed)

    hash_buf = zlib.crc32(plain[:crc_len]) & 0xffffffff

    padded = packed + b"\x00" * ((16 - len(packed) % 16) % 16)

    data_buf = AES.new(key, AES.MODE_CBC, salt_buf).encrypt(padded)
    data_len = len(data_buf)

  line = "$7z$%d$%d$%d$%s$%d$%s$%d$%d$%d$%s$%d$%s" % (
    data_type, num_cycle_power, seven_zip_salt_len, seven_zip_salt_buf, salt_len,
    salt_buf.hex(), hash_buf, data_len, unpack_size, data_buf.hex(), crc_len,
    coder_props.hex())

  if len(filter_props) > 0:
    line += "$%s" % filter_props.hex()

  return line


def module_verify_hash(line):
  if line[0:4] != b"$7z$":
    return None

  hash_in = line.split(b":", 1)

  if len(hash_in) != 2:
    return None

  fields = hash_in[0].decode(errors="replace").split("$")

  # ['', '7z', p, num_cycle_power, sz_salt_len, sz_salt_buf, salt_len, salt, crc, data_len, unpack_size, data]
  # followed by crc_len and the coder attributes for compressed data, and the filter attributes if a
  # filter ran before the compressor

  if (len(fields) in (12, 14, 15)) == False or fields[1] != "7z":
    return None

  data_type = int(fields[2])

  if (data_type == 0) != (len(fields) == 12):
    return None

  word = hash_in[1]

  iterations         = fields[3]
  seven_zip_salt_len = fields[4]
  seven_zip_salt_buf = fields[5]
  salt_len           = fields[6]
  salt               = bytes.fromhex(fields[7])
  data_len           = fields[9]
  unpack_size        = fields[10]
  data_buf           = bytes.fromhex(fields[11])

  crc_len      = fields[12] if len(fields) > 12 else None
  coder_props  = bytes.fromhex(fields[13]) if len(fields) > 13 else None
  filter_props = bytes.fromhex(fields[14]) if len(fields) > 14 else b""

  new_hash = module_generate_hash(word, salt, iterations, seven_zip_salt_len,
                                  seven_zip_salt_buf, salt_len, data_len,
                                  unpack_size, data_buf, data_type, crc_len,
                                  coder_props, filter_props)

  return (new_hash, word)
