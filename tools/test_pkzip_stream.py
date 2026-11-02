#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Test direct ZIP input with synthetic encrypted members."""

import argparse
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import time
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

    def run(name, value, *, dictionary=words, expected=0, options=(), message=None, recovered=password, expected_hash=None):
      nonlocal checks
      outfile = work / (name + '.found')
      command = [str(args.binary.resolve()), '-m', '17240', '-a', '0', str(value), str(dictionary),
                 '--restore-disable', '--cache-path', str(work / 'kernels'), '-d', args.device,
                 '-w', '1', '--potfile-disable', '--outfile', str(outfile),
                 '--outfile-format=' + ('1,3' if expected_hash is not None else '3'),
                 *args.backend_arg, *options]
      result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=180)
      output = result.stdout + result.stderr
      if expected is None:
        assert os.name == 'nt' or result.returncode >= 0, (name, result.returncode, output)
        assert (result.returncode & 0xff) in (0xff, 0xfe, 0xf4), (name, result.returncode, output)
      else:
        assert result.returncode == expected, (name, result.returncode, output)
      if message:
        assert message in output, (name, output)
      if expected == 0:
        encoded = outfile.read_text(encoding='utf-8').strip()
        wanted = recovered.hex()
        if expected_hash is not None:
          wanted = str(expected_hash) + ':' + wanted
        assert encoded == wanted, (name, encoded, wanted)
      else:
        assert not outfile.exists() or outfile.stat().st_size == 0, name
      checks += 1
      print('%s: passed' % name, flush=True)

    def inline_member(data, pwd=password, method=0):
      crc = zlib.crc32(data)
      compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
      packed = compressor.compress(data) + compressor.flush() if method == 8 else data
      payload = ZipCrypto(pwd).encrypt(bytes(range(11)) + bytes([crc >> 24]) + packed)
      return '$pkzip-stream$*%x*0*%x*%x*%08x*%02x*%s*-' % (
        method, len(payload), len(data), crc, crc >> 24, payload.hex())

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
    for size in range(5):
      data = b'x' * size
      archive = work / ('stored-%d.zip' % size)
      make_archive(archive, [member(data)])
      run('stored-auto-%d' % size, archive, expected=0 if size == 4 else None)
      run('stored-explicit-%d' % size, archive, options=['--pkzip-member-index=0'],
          expected=0 if size == 4 else None,
          message='member is empty' if size == 0 else 'at least 4 bytes' if size < 4 else None)
      inline = inline_member(data)
      run('stored-inline-%d' % size, inline, expected=0 if size == 4 else None)
      if size < 4:
        make_archive(archive, [member(data), member(b'verify', name='valid.bin')])
        run('skip-short-%d' % size, archive)

    inline = inline_member(b'x', method=8)
    run('short-deflate-inline', inline, expected_hash=inline)
    archive = work / 'short-deflate.zip'
    make_archive(archive, [member(b'x', method=8)])
    run('short-deflate-archive', archive)
    archive = work / '\u6837\u672c archive.zip'
    make_archive(archive, [member()])
    run('unicode', archive, expected_hash=archive,
        message='Use --keep-guessing to continue attack')
    encoded = (work / 'unicode.found').read_text(encoding='utf-8').strip().rsplit(':', 1)[0]
    run('reload-archive-path', encoded, expected_hash=archive)
    make_archive(archive, [member(b'skipped'), member(name='chosen.bin')])
    run('encode-explicit-member', archive, options=['--pkzip-member-index=1'], expected_hash=archive)

    for change in ('delete', 'truncate', 'replace'):
      archive = work / ('source-' + change + '.zip')
      make_archive(archive, [member()])
      log = work / ('source-' + change + '.log')
      outfile = work / ('source-' + change + '.found')
      command = [str(args.binary.resolve()), '-m', '17240', '-a', '3', str(archive), '?d' * 10,
                 '--restore-disable', '--cache-path', str(work / 'kernels'), '-d', args.device,
                 '-w', '1', '--potfile-disable', '--status', '--status-json', '--status-timer=1',
                 '--outfile', str(outfile), *args.backend_arg]
      with log.open('w', encoding='utf-8') as output:
        process = subprocess.Popen(command, cwd=root, stdout=output, stderr=subprocess.STDOUT)
        try:
          deadline = time.monotonic() + 180
          while re.search(r'"status"\s*:\s*3', log.read_text(encoding='utf-8', errors='replace')) is None:
            assert process.poll() is None, log.read_text(encoding='utf-8', errors='replace')
            assert time.monotonic() < deadline, 'Timed out waiting for attack'
            time.sleep(0.05)
          if change == 'delete':
            archive.unlink()
          elif change == 'truncate':
            archive.write_bytes(b'PK')
          else:
            replacement = work / 'replacement.zip'
            replacement.write_bytes(archive.read_bytes())
            if os.name == 'nt':
              # ReplaceFileW permits replacing an archive with open read handles.
              import ctypes
              kernel = ctypes.WinDLL('kernel32', use_last_error=True)
              replace = kernel.ReplaceFileW
              replace.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                  ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
              if not replace(str(archive), str(replacement), None, 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
            else:
              replacement.replace(archive)
          rc = process.wait(timeout=180)
        finally:
          if process.poll() is None:
            process.kill()
            process.wait()
      output = log.read_text(encoding='utf-8', errors='replace')
      assert os.name == 'nt' or rc >= 0, (change, rc, output)
      assert (rc & 0xff) == 0xf4, (change, rc, output)
      assert output.count('PKZIP source failure:') == 1, (change, output)
      assert not outfile.exists() or outfile.stat().st_size == 0, change
      checks += 1
      print('source-%s: passed' % change, flush=True)

    inline = inline_member(b'data', pwd=b'')
    words.write_bytes(b'\n')
    run('empty-password', inline, recovered=b'')
    empty = '$pkzip-stream$*0*0*c*0*00000000*00*963adfae487332dce29a87cc*-'
    run('reject-empty-inline', empty, expected=None)
    for reference in ['00', '2f746d702f66696c65', '5c5c6578616d706c652e696e76616c69645c73686172655c78']:
      run('reject-reference-' + reference[:4], inline[:-1] + reference, expected=None)
  print('%d direct ZIP checks passed.' % checks)


if __name__ == '__main__':
  main()
