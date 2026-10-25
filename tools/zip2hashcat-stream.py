#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Extract a mode 17240 reference for a traditional encrypted ZIP member."""

import argparse
from pathlib import Path
import struct
import zipfile


def extract(path, member=None):
  path = Path(path).resolve(strict=True)
  reference = str(path).encode('utf-8')

  if len(reference) > 4095:
    raise ValueError('The source path exceeds 4095 UTF-8 bytes.')

  with zipfile.ZipFile(path) as archive:
    members = [info for info in archive.infolist() if not info.is_dir()]

    if member is not None:
      members = [info for info in members if info.filename == member]

      if len(members) != 1:
        raise ValueError('--member must identify exactly one ZIP member.')

    members = [info for info in members if info.flag_bits & 1
               and not info.flag_bits & 0x2040 and info.compress_type in (0, 8)]

    if not members:
      raise ValueError('No traditional encrypted stored or DEFLATE member was found.')

    info = min(members, key=lambda value: value.compress_size)

    if info.compress_size < 12:
      raise ValueError('The encrypted member is shorter than its encryption header.')

    source = archive.fp
    source.seek(info.header_offset)
    header = source.read(30)

    if len(header) != 30 or header[:4] != b'PK\x03\x04':
      raise ValueError('Invalid ZIP local header.')

    _, _, flags, method, timestamp, _, _, _, _, name_len, extra_len = struct.unpack('<4s5H3I2H', header)

    if method != info.compress_type or (flags & 0x2049) != (info.flag_bits & 0x2049):
      raise ValueError('The local and central ZIP encryption metadata disagree.')

    offset = info.header_offset + 30 + name_len + extra_len

    if offset + info.compress_size > path.stat().st_size:
      raise ValueError('The encrypted member extends past the source file.')

    source.seek(offset)
    sample = source.read(min(256, info.compress_size))

    if len(sample) != min(256, info.compress_size):
      raise ValueError('The encrypted sample is truncated.')

    check = timestamp >> 8 if flags & 8 else info.CRC >> 24

    return '$pkzip-stream$*%x*%x*%x*%x*%08x*%02x*%s*%s' % (
      method, offset, info.compress_size, info.file_size, info.CRC, check,
      sample.hex(), reference.hex())


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('archive', type=Path)
  parser.add_argument('--member', help='Exact member name. Defaults to the smallest supported encrypted member.')
  args = parser.parse_args()

  try:
    value = extract(args.archive, args.member)
  except (OSError, ValueError, zipfile.BadZipFile) as error:
    parser.exit(1, 'ERROR: %s\n' % error)

  print(value)


if __name__ == '__main__':
  main()
