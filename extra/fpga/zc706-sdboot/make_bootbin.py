#!/usr/bin/env python3
#
# Author......: See docs/credits.txt
# License.....: MIT
#

import os
import struct
import sys

IMAGE_HEADER_TABLE = 0x8c0
IMAGE_HEADER_0     = 0x900
IMAGE_HEADER_1     = 0x940
PARTITION_TABLE    = 0xc80
FSBL_OFFSET        = 0x1700

REGINIT_OFFSET = 0xa0
REGINIT_PAIRS  = 256

PARTITION_ALIGN = 64
LENGTH_ALIGN    = 8

ATTR_FSBL      = 0x10
ATTR_BITSTREAM = 0x20

def swap32 (data: bytes) -> bytes:
  if (len (data) % 4) != 0:
    raise ValueError ("bitstream payload is not a whole number of 32-bit words")

  out = bytearray (len (data))

  for i in range (0, len (data) - (len (data) % 4), 4):
    out[i + 0] = data[i + 3]
    out[i + 1] = data[i + 2]
    out[i + 2] = data[i + 1]
    out[i + 3] = data[i + 0]

  return bytes (out)

def checksum (words: list) -> int:
  total = 0

  for w in words:
    total = (total + w) & 0xffffffff

  result = (~total) & 0xffffffff

  return result

def bit_payload (path: str) -> bytes:
  raw = open (path, "rb").read ()

  pos = 0

  if len (raw) < 4:
    raise ValueError ("%s has a truncated .bit header" % path)

  header_len = struct.unpack_from (">H", raw, pos)[0]

  pos += 2 + header_len
  pos += 2

  if pos > len (raw):
    raise ValueError ("%s has a truncated .bit header" % path)

  while pos < len (raw):
    key = raw[pos]

    pos += 1

    if key == ord ("e"):
      if pos + 4 > len (raw):
        raise ValueError ("%s has a truncated bitstream length" % path)

      length = struct.unpack_from (">I", raw, pos)[0]

      pos += 4

      if length == 0:
        raise ValueError ("%s has an empty bitstream payload" % path)

      if pos + length > len (raw):
        raise ValueError ("%s has a truncated bitstream payload" % path)

      result = raw[pos : pos + length]

      return result

    if pos + 2 > len (raw):
      raise ValueError ("%s has a truncated .bit field" % path)

    field_len = struct.unpack_from (">H", raw, pos)[0]

    pos += 2 + field_len

    if pos > len (raw):
      raise ValueError ("%s has a truncated .bit field" % path)

  raise ValueError ("%s has no 'e' field, so it is not a .bit" % path)

def fsbl_payload (path: str) -> bytes:
  raw = open (path, "rb").read ()

  if (len (raw) < 0x34) or (raw[0:4] != b"\x7fELF"):
    raise ValueError ("%s is not a complete ELF header" % path)

  if (raw[4:6] != b"\x01\x01") or (struct.unpack_from ("<H", raw, 0x12)[0] != 40):
    raise ValueError ("%s is not a 32-bit little-endian ARM ELF" % path)

  e_phoff  = struct.unpack_from ("<I", raw, 0x1c)[0]
  e_phentsize = struct.unpack_from ("<H", raw, 0x2a)[0]
  e_phnum  = struct.unpack_from ("<H", raw, 0x2c)[0]

  out = b""

  for i in range (e_phnum):
    off = e_phoff + (i * e_phentsize)

    p_type, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz = struct.unpack_from ("<IIIIII", raw, off)

    if p_type != 1: continue
    if p_filesz == 0: continue

    if p_offset + p_filesz > len (raw):
      raise ValueError ("%s has a truncated loadable segment" % path)

    out += raw[p_offset : p_offset + p_filesz]

  if len (out) == 0:
    raise ValueError ("%s has no loadable segment" % path)

  return out

def encode_name (name: str) -> bytes:
  padded = name.encode ("ascii") + b"\x00"

  while (len (padded) % 4) != 0:
    padded += b"\x00"

  padded += b"\x00" * 4

  out = b""

  for i in range (0, len (padded), 4):
    out += padded[i : i + 4][::-1]

  return out

def partition_header (length: int, data_offset: int, attributes: int, image_header: int) -> bytes:
  words = [
    length // 4,
    length // 4,
    length // 4,
    0,
    0,
    data_offset // 4,
    attributes,
    1,
    0,
    image_header // 4,
    0, 0, 0, 0, 0,
  ]

  out = b""

  for w in words: out += struct.pack ("<I", w)

  out += struct.pack ("<I", checksum (words))

  return out

def build (bit_path: str, fsbl_path: str) -> bytes:
  fsbl = fsbl_payload (fsbl_path)
  bits = swap32 (bit_payload (bit_path))

  def align (n, to): return (n + (to - 1)) & ~(to - 1)

  fsbl_space = align (len (fsbl), PARTITION_ALIGN)
  bits_off   = FSBL_OFFSET + fsbl_space
  bits_space = align (len (bits), PARTITION_ALIGN)

  image = bytearray (b"\xff" * (bits_off + bits_space))

  for i in range (8): struct.pack_into ("<I", image, i * 4, 0xeafffffe)

  header = [
    0xaa995566,
    0x584c4e58,
    0x00000000,
    0x01010000,
    FSBL_OFFSET,
    len (fsbl),
    0x00000000,
    0x00000000,
    len (fsbl),
    0x00000001,
  ]

  for i, w in enumerate (header): struct.pack_into ("<I", image, 0x20 + (i * 4), w)

  struct.pack_into ("<I", image, 0x48, checksum (header))

  for i in range (0x4c, REGINIT_OFFSET, 4): struct.pack_into ("<I", image, i, 0)

  struct.pack_into ("<I", image, 0x98, IMAGE_HEADER_TABLE)
  struct.pack_into ("<I", image, 0x9c, PARTITION_TABLE)

  for i in range (REGINIT_PAIRS):
    off = REGINIT_OFFSET + (i * 8)

    struct.pack_into ("<I", image, off + 0, 0xffffffff)
    struct.pack_into ("<I", image, off + 4, 0x00000000)

  table = [0x01020000, 2, PARTITION_TABLE // 4, IMAGE_HEADER_0 // 4, 0, 0xffffffff]

  for i, w in enumerate (table): struct.pack_into ("<I", image, IMAGE_HEADER_TABLE + (i * 4), w)

  for i, (this, nxt, pht, name) in enumerate ((
      (IMAGE_HEADER_0, IMAGE_HEADER_1, PARTITION_TABLE,        os.path.basename (fsbl_path)),
      (IMAGE_HEADER_1, 0,              PARTITION_TABLE + 0x40, os.path.basename (bit_path)))):

    struct.pack_into ("<I", image, this + 0x00, nxt // 4)
    struct.pack_into ("<I", image, this + 0x04, pht // 4)
    struct.pack_into ("<I", image, this + 0x08, 0)
    struct.pack_into ("<I", image, this + 0x0c, 1)

    encoded = encode_name (name)

    image[this + 0x10 : this + 0x10 + len (encoded)] = encoded

  ph0 = partition_header (align (len (fsbl), LENGTH_ALIGN), FSBL_OFFSET, ATTR_FSBL,      IMAGE_HEADER_0)
  ph1 = partition_header (align (len (bits), LENGTH_ALIGN), bits_off,    ATTR_BITSTREAM, IMAGE_HEADER_1)

  image[PARTITION_TABLE + 0x00 : PARTITION_TABLE + 0x40] = ph0
  image[PARTITION_TABLE + 0x40 : PARTITION_TABLE + 0x80] = ph1

  for i in range (15): struct.pack_into ("<I", image, PARTITION_TABLE + 0x80 + (i * 4), 0)

  image[FSBL_OFFSET : FSBL_OFFSET + len (fsbl)] = fsbl
  image[bits_off    : bits_off    + len (bits)] = bits

  for off in range (bits_off + len (bits), bits_off + align (len (bits), LENGTH_ALIGN), 4):
    struct.pack_into ("<I", image, off, 0x20000000)

  result = bytes (image)

  return result

def main () -> int:
  if (len (sys.argv) < 2) or (sys.argv[1] in ("-h", "--help")):
    print ("usage: %s design.bit [BOOT.BIN]" % sys.argv[0])
    print ()
    print ("Packages a ZC706 bitstream with the FSBL into a Zynq-7000 BOOT.BIN.")
    print ("Writes BOOT.BIN next to this script when no output path is given.")
    print ("Requires Python only; Vivado and bootgen are not used.")
    print ()
    print ("Copy the result to the FAT32 first partition of an MBR SD card as BOOT.BIN.")
    print ("The BootROM requires this exact layout and name. See README.md for SW11 settings.")

    return 1

  here = os.path.dirname (os.path.abspath (__file__))

  bit_path  = sys.argv[1]
  out_path  = sys.argv[2] if len (sys.argv) > 2 else os.path.join (here, "BOOT.BIN")
  fsbl_path = os.path.join (here, "fsbl.elf")

  if os.path.exists (bit_path) == False:
    print ("bitstream not found: %s" % bit_path)

    return 1

  if os.path.exists (fsbl_path) == False:
    print ("fsbl.elf not found beside this script; rebuild it with 'xsct build_fsbl.tcl'")

    return 1

  try:
    image = build (bit_path, fsbl_path)
  except (OSError, ValueError, struct.error) as exc:
    print ("cannot build BOOT.BIN: %s" % exc, file = sys.stderr)

    return 1

  open (out_path, "wb").write (image)

  print ("")
  print ("  bitstream : %s" % bit_path)
  print ("  BOOT.BIN  : %s (%d bytes)" % (out_path, len (image)))
  print ("")
  print ("  Copy it to the FAT32 partition of an SD card as BOOT.BIN, then set SW11 to SD boot:")
  print ("  pole 1 Down, 2 Down, 3 UP, 4 UP, 5 Down (UG954 Table 1-2, Down is 0).")
  print ("")

  return 0

if __name__ == "__main__":
  sys.exit (main ())
