#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Test direct ZIP input with synthetic encrypted members."""

import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent / 'test_modules'))

from lib.pkzip import ZipCrypto


def make_archive(path, members, *, zip64=False, descriptor=False, signature=True):
  body = bytearray()
  directory = bytearray()
  for name, content, password, method, strategy, corrupt_crc in members:
    name = name.encode('utf-8')
    crc = zlib.crc32(content) ^ corrupt_crc
    flags = 0x801 | (8 if descriptor else 0)
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15, strategy=strategy)
    data = compressor.compress(content) + compressor.flush() if method == 8 else content
    check = 0 if descriptor else crc >> 24
    payload = ZipCrypto(password).encrypt(bytes(range(11)) + bytes([check]) + data)
    offset = len(body)
    extra = struct.pack('<HHQQ', 1, 16, len(content), len(payload)) if zip64 else b''
    sizes = (0, 0, 0) if descriptor else (crc, len(payload), len(content))
    if zip64:
      sizes = (sizes[0], 0xffffffff, 0xffffffff)
    body += struct.pack('<4s5H3I2H', b'PK\x03\x04', 45 if zip64 else 20,
                        flags, method, 0, 33, *sizes, len(name), len(extra)) + name + extra + payload
    if descriptor:
      body += b'PK\x07\x08' if signature else b''
      body += struct.pack('<IQQ' if zip64 else '<III', crc, len(payload), len(content))
    extra = struct.pack('<HHQQQ', 1, 24, len(content), len(payload), offset) if zip64 else b''
    packed, unpacked, local = (0xffffffff,) * 3 if zip64 else (len(payload), len(content), offset)
    directory += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 45, 45 if zip64 else 20,
                             flags, method, 0, 33, crc, packed, unpacked,
                             len(name), len(extra), 0, 0, 0, 0, local) + name + extra
  offset = len(body)
  body += directory
  count = len(members)
  if zip64:
    position = len(body)
    body += struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44, 45, 45, 0, 0,
                        count, count, len(directory), offset)
    body += struct.pack('<4sIQI', b'PK\x06\x07', 0, position, 1)
  body += struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0,
                      0xffff if zip64 else count, 0xffff if zip64 else count,
                      0xffffffff if zip64 else len(directory), 0xffffffff if zip64 else offset, 0)
  path.write_bytes(body)


def main():
  root = Path(__file__).resolve().parent.parent
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--binary', type=Path, default=root / ('hashcat.exe' if os.name == 'nt' else 'hashcat'))
  parser.add_argument('--device', default='1')
  parser.add_argument('--size-mib', type=int, default=1)
  parser.add_argument('--backend-arg', action='append', default=[])
  args = parser.parse_args()
  if args.size_mib < 1:
    parser.error('--size-mib must be at least 1')
  password = b'stream-test'
  content = os.urandom(args.size_mib * 1024 * 1024)
  checks = 0
  with tempfile.TemporaryDirectory(prefix='pkzip_stream_') as temporary:
    work = Path(temporary)
    (work / 'kernels').mkdir()
    words = work / 'words.txt'
    words.write_bytes(password + b'\n')
    wrong = work / 'wrong.txt'
    wrong.write_bytes(b'wrong-password\n')

    def run(name, value, *, dictionary=words, expected=0, options=(), message=None, recovered=password):
      nonlocal checks
      outfile = work / (name + '.found')
      command = [str(args.binary.resolve()), '-m', '17240', '-a', '0', str(value), str(dictionary),
                 '--restore-disable', '--cache-path', str(work / 'kernels'), '-d', args.device,
                 '-w', '1', '--potfile-disable', '--outfile', str(outfile), '--outfile-format=3',
                 *args.backend_arg, *options]
      result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=180)
      output = result.stdout + result.stderr
      if expected is None:
        assert result.returncode not in (0, 1), (name, result.returncode, output)
      else:
        assert result.returncode == expected, (name, result.returncode, output)
      if message:
        assert message in output, (name, output)
      if expected == 0:
        assert outfile.read_text(encoding='ascii').strip() == recovered.hex(), name
      else:
        assert not outfile.exists() or outfile.stat().st_size == 0, name
      checks += 1
      print('%s: passed' % name, flush=True)

    def member(data=content, method=0, strategy=zlib.Z_DEFAULT_STRATEGY, name='member.bin', pwd=password, crc=0):
      return (name, data, pwd, method, strategy, crc)

    for label, method, strategy in [('stored', 0, 0), ('fixed', 8, zlib.Z_FIXED), ('dynamic', 8, zlib.Z_DEFAULT_STRATEGY)]:
      test_content = content if method == 0 else (bytes(range(251)) * ((len(content) + 250) // 251))[:len(content)]
      if method == 8:
        compressor = zlib.compressobj(6, zlib.DEFLATED, -15, strategy=strategy)
        data = compressor.compress(test_content) + compressor.flush()
        assert (data[0] >> 1) & 3 == (1 if strategy == zlib.Z_FIXED else 2)
      for wide, descriptor, signature in [(False, False, True), (False, True, True),
                                           (False, True, False), (True, False, True), (True, True, True)]:
        name = '%s-%d-%d-%d' % (label, wide, descriptor, signature)
        archive = work / (name + '.zip')
        make_archive(archive, [member(data=test_content, method=method, strategy=strategy)],
                     zip64=wide, descriptor=descriptor, signature=signature)
        with zipfile.ZipFile(archive) as reader:
          assert reader.read('member.bin', pwd=password) == test_content
        run(name, archive)
    archive = work / 'descriptor-crc-signature.zip'
    marker_content = bytes.fromhex('ac0a7ad5')
    assert zlib.crc32(marker_content) == 0x08074b50
    make_archive(archive, [member(marker_content)], descriptor=True, signature=False)
    with zipfile.ZipFile(archive) as reader:
      assert reader.read('member.bin', pwd=password) == marker_content
    run('unsigned-descriptor-crc-signature', archive)
    archive = work / 'mixed.zip'
    make_archive(archive, [member(b''), member(name='../../never-open.bin')])
    run('skip-empty', archive)
    run('explicit-member', archive, options=['--pkzip-member-index=1'])
    original = archive.read_bytes()
    run('reject-remove', archive, options=['--remove'], expected=None, message='does not support --remove')
    assert archive.read_bytes() == original
    run('reject-empty', archive, options=['--pkzip-member-index=0'], expected=None, message='member is empty')
    run('reject-index', archive, options=['--pkzip-member-index=2'], expected=None, message='outside the central directory')
    run('wrong-password', archive, dictionary=wrong, expected=1)
    make_archive(archive, [member(crc=1)])
    run('wrong-crc', archive, expected=1)
    make_archive(archive, [member()])
    raw = bytearray(archive.read_bytes())
    raw[len(content) // 2] ^= 1
    archive.write_bytes(raw)
    run('damaged-data', archive, expected=1)
    archive.write_bytes(raw[:512])
    run('truncated-archive', archive, expected=None)
    archive = work / '\u6837\u672c.zip'
    make_archive(archive, [member()])
    run('unicode', archive)
    payload = ZipCrypto(b'').encrypt(bytes(range(11)) + bytes([zlib.crc32(b'x') >> 24]) + b'x')
    inline = '$pkzip-stream$*0*0*d*1*%08x*%02x*%s*-' % (zlib.crc32(b'x'), zlib.crc32(b'x') >> 24, payload.hex())
    words.write_bytes(b'\n')
    run('empty-password', inline, recovered=b'')
    empty = '$pkzip-stream$*0*0*c*0*00000000*00*963adfae487332dce29a87cc*-'
    run('reject-empty-inline', empty, expected=None)
    for reference in ['00', '2f746d702f66696c65', '5c5c6578616d706c652e696e76616c69645c73686172655c78']:
      run('reject-reference-' + reference[:4], inline[:-1] + reference, expected=None)
  print('%d direct ZIP checks passed.' % checks)


if __name__ == '__main__':
  main()
