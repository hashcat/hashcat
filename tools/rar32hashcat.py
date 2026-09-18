#!/usr/bin/env python3

#
# Author......: See docs/credits.txt
# License.....: MIT
#

# Reads a password protected RAR3 archive and writes the hash lines for it. The archive layout is
# written from the published RAR 3.93 technical note:
# https://raw.githubusercontent.com/php/pecl-file_formats-rar/master/technote.txt
#
# The packing method byte picks the mode: a stored file is -m 23700, a compressed one -m 23800. An
# archive written by rar -hp has encrypted headers and cannot be read. A solid one, rar -s, gets a
# line for its first file only.

import sys

from argparse import ArgumentParser

MARKER = bytes ([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00])

HEAD_TYPE_MAIN = 0x73
HEAD_TYPE_FILE = 0x74


FLAG_ADD_SIZE      = 0x8000


FLAG_ENCRYPTED     = 0x0004
FLAG_SOLID         = 0x0010
FLAG_LARGE         = 0x0100
FLAG_UNICODE_NAME  = 0x0200
FLAG_SALT          = 0x0400
FLAG_EXT_TIME      = 0x1000

METHOD_STORE       = 0x30

# The -m 23800 parser in src/modules/module_23800.c refuses anything outside these.

PACK_SIZE_MAX   = 327680
UNPACK_SIZE_MAX = 655360

BASE_FILE_HEAD_SIZE = 32


def u16 (buf: bytes, off: int) -> int:
  return int.from_bytes (buf[off:off + 2], "little")


def u32 (buf: bytes, off: int) -> int:
  return int.from_bytes (buf[off:off + 4], "little")


class Rar3Error (Exception):
  pass


def find_marker (data: bytes) -> int:

  pos = data.find (MARKER)

  if pos < 0:
    raise Rar3Error ("no RAR marker block found, so this is not a RAR archive")

  return pos


def read_file_header (data: bytes, off: int):

  if (off + 7) > len (data):
    raise Rar3Error ("truncated block header")

  head_type  = data[off + 2]
  head_flags = u16 (data, off + 3)
  head_size  = u16 (data, off + 5)

  if head_size < 7:
    raise Rar3Error ("block header size %d is below the 7 byte minimum" % head_size)

  if head_type != HEAD_TYPE_FILE:
    block_size = head_size

    if head_flags & FLAG_ADD_SIZE:
      if (off + 11) > len (data):
        raise Rar3Error ("truncated block header")

      block_size += u32 (data, off + 7)

    return None, block_size

  if (off + BASE_FILE_HEAD_SIZE) > len (data):
    raise Rar3Error ("truncated file header")

  pack_size   = u32 (data, off + 7)
  unpack_size = u32 (data, off + 11)
  file_crc    = data[off + 16:off + 20]
  method      = data[off + 25]
  name_size   = u16 (data, off + 26)


  pos = off + BASE_FILE_HEAD_SIZE

  if head_flags & FLAG_LARGE:
    if (pos + 8) > len (data):
      raise Rar3Error ("truncated file header")

    pack_size   += u32 (data, pos + 0) << 32
    unpack_size += u32 (data, pos + 4) << 32

    pos += 8

  name = data[pos:pos + name_size]

  pos += name_size

  salt = None

  if head_flags & FLAG_SALT:
    if (pos + 8) > len (data):
      raise Rar3Error ("truncated file header, the salt is cut off")

    salt = data[pos:pos + 8]


  if head_flags & FLAG_UNICODE_NAME:
    name = name.split (b"\0")[0]

  header = {
    "flags":       head_flags,
    "head_size":   head_size,
    "pack_size":   pack_size,
    "unpack_size": unpack_size,
    "file_crc":    file_crc,
    "method":      method,
    "name":        name.decode ("utf-8", "replace"),
    "salt":        salt,
    "data_off":    off + head_size,
  }

  return header, head_size + pack_size


def hash_lines (data: bytes, quiet: bool):
  off = find_marker (data)


  off += 7

  if (off + 7) > len (data):
    raise Rar3Error ("archive ends before its header")

  if data[off + 2] != HEAD_TYPE_MAIN:
    raise Rar3Error ("the block after the marker is not an archive header")

  main_flags = u16 (data, off + 3)

  if main_flags & 0x0080:
    raise Rar3Error ("the archive has encrypted headers, written by rar -hp, and cannot be read without the password")

  off += u16 (data, off + 5)

  lines = []

  while off < len (data):
    header, block_size = read_file_header (data, off)

    if block_size < 7:
      raise Rar3Error ("block at offset %d claims an impossible size" % off)

    off += block_size

    if header is None:
      continue

    name = header["name"]

    if (header["flags"] & FLAG_ENCRYPTED) == 0:
      if quiet == False:
        print ("skipping '%s': not encrypted" % name, file = sys.stderr)

      continue

    if header["salt"] is None:
      if quiet == False:
        print ("skipping '%s': encrypted without a salt, which RAR 3.x always writes" % name, file = sys.stderr)

      continue

    if header["method"] == METHOD_STORE:
      if quiet == False:
        print ("skipping '%s': stored rather than compressed, so it is -m 23700 and not this mode" % name, file = sys.stderr)

      continue

    # A solid file carries on from the one before, so a line for it could only report a false miss.

    if (header["flags"] & FLAG_SOLID) != 0:
      if quiet == False:
        print ("skipping '%s': solid, so its stream continues the file before it and a hash line cannot carry what it reaches back into" % name, file = sys.stderr)

      continue

    pack_size   = header["pack_size"]
    unpack_size = header["unpack_size"]

    limits = (("packed", pack_size, PACK_SIZE_MAX), ("unpacked", unpack_size, UNPACK_SIZE_MAX))

    over = next(((w, got, cap) for w, got, cap in limits if got > cap), None)

    if over is not None:
      if quiet == False:
        print ("skipping '%s': %s size %d is above the %d that -m 23800 accepts" % (name, over[0], over[1], over[2]), file = sys.stderr)

      continue

    if (pack_size % 16) != 0:
      if quiet == False:
        print ("skipping '%s': packed size %d is not a multiple of the 16 byte AES block" % (name, pack_size), file = sys.stderr)

      continue

    packed = data[header["data_off"]:header["data_off"] + pack_size]

    if len (packed) != pack_size:
      raise Rar3Error ("'%s' claims %d packed bytes and the archive holds %d" % (name, pack_size, len (packed)))


    line = "$RAR3$*1*%s*%s*%d*%d*1*%s*%02x" % (
      header["salt"].hex (),
      header["file_crc"].hex (),
      pack_size,
      unpack_size,
      packed.hex (),
      header["method"])

    lines.append ((name, line))

  return lines


def main () -> int:
  parser = ArgumentParser (description = "extract -m 23800 hash lines from a password protected RAR3 archive")

  parser.add_argument ("archive", nargs = "+", help = "the .rar file to read")
  parser.add_argument ("--quiet", action = "store_true", help = "do not say why a file was skipped")
  parser.add_argument ("--names", action = "store_true", help = "print the file name in front of each line")

  args = parser.parse_args ()

  rc = 0

  for path in args.archive:
    try:
      with open (path, "rb") as fd:
        data = fd.read ()

      lines = hash_lines (data, args.quiet)
    except (OSError, Rar3Error) as e:
      print ("%s: %s" % (path, e), file = sys.stderr)

      rc = 1

      continue

    if len (lines) == 0:
      if args.quiet == False:
        print ("%s: nothing in this archive is a compressed, password protected file" % path, file = sys.stderr)

      rc = 1

    for name, line in lines:
      if args.names == True:
        print ("%s:%s" % (name, line))
      else:
        print (line)

  return rc


if __name__ == "__main__":
  sys.exit (main ())
