#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Exercise external PKZIP references with real encrypted data and negative cases."""

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent / 'test_modules'))

from lib.pkzip import ZipCrypto


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
  crc = zlib.crc32(content)
  checks = 0
  (root / 'cache').mkdir(exist_ok=True)

  with tempfile.TemporaryDirectory(prefix='pkzip_stream_', dir=root / 'cache') as temporary:
    work = Path(temporary)
    (work / 'kernels').mkdir()
    words = work / 'words.txt'
    words.write_bytes(password + b'\n')
    wrong = work / 'wrong.txt'
    wrong.write_bytes(b'wrong-password\n')

    def run(name, value, dictionary=words, expected=0, show=False):
      nonlocal checks
      reference = work / (name + '.hash')
      reference.write_text(value + '\n', encoding='ascii')
      outfile = work / (name + '.found')
      command = [str(args.binary), '-m', '17240', str(reference),
                 '--restore-disable', '--cache-path', str(work / 'kernels'), '-d', args.device,
                 '-w', '1', '--runtime', '30', *args.backend_arg]

      if show:
        command.append('--show')
      else:
        command += ['--potfile-disable', '-a', '0', str(dictionary), '--outfile', str(outfile), '--outfile-format=3']

      result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                              encoding='utf-8', errors='replace')

      if expected is None:
        assert result.returncode != 0, name
        assert 'No hashes loaded' in result.stdout + result.stderr, name
      else:
        assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)

      if expected == 0:
        assert outfile.read_text(encoding='ascii').strip() == password.hex(), name
      else:
        assert not outfile.exists() or outfile.stat().st_size == 0, name

      checks += 1
      print('%s: passed' % name, flush=True)

    records = {}

    def check_extractor(method, data, descriptor=False):
      flags = 9 if descriptor else 1
      check = 0 if descriptor else crc >> 24
      payload = ZipCrypto(password).encrypt(os.urandom(11) + bytes([check]) + data)
      name = b'member.bin'
      sizes = (0, 0, 0) if descriptor else (crc, len(payload), len(content))
      local = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flags, method, 0, 33,
                          *sizes, len(name), 0) + name
      body = local + payload

      if descriptor:
        body += struct.pack('<4s3I', b'PK\x07\x08', crc, len(payload), len(content))

      central = struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 20, 20, flags, method, 0, 33,
                            crc, len(payload), len(content), len(name), 0, 0, 0, 0, 0, 0) + name
      end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(body), 0)
      archive = work / ('archive-%d-%d.zip' % (method, flags))
      archive.write_bytes(body + central + end)

      with zipfile.ZipFile(archive) as reader:
        assert reader.read('member.bin', pwd=password) == content

      command = [sys.executable, str(root / 'tools/zip2hashcat-stream.py'), str(archive),
                 '--member', 'member.bin']
      result = subprocess.run(command, capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
      run('extractor-%d-%d' % (method, flags), result.stdout.strip())

    for method in (0, 8):
      if method == 8:
        compressor = zlib.compressobj(0, zlib.DEFLATED, -15)
        data = compressor.compress(content) + compressor.flush()
      else:
        data = content

      payload = ZipCrypto(password).encrypt(os.urandom(11) + bytes([crc >> 24]) + data)
      source = work / ('member-%d.bin' % method)
      source.write_bytes(b'reference-prefix' + payload)
      sample = payload[:256]
      value = '$pkzip-stream$*%d*10*%x*%x*%08x*%02x*%s*%s' % (
        method, len(payload), len(content), crc, crc >> 24, sample.hex(), str(source).encode('utf-8').hex())
      records[method] = (source, value)
      run('method-%d' % method, value)
      check_extractor(method, data)

      if method == 8:
        check_extractor(method, data, descriptor=True)

    run('wrong-password', records[0][1], wrong, expected=1)
    parts = records[8][1].split('*')
    parts[5] = '%08x' % (crc ^ 1)
    run('wrong-crc', '*'.join(parts), expected=1)

    source, value = records[8]
    with source.open('r+b') as file:
      file.seek(-32, 2)
      byte = file.read(1)
      file.seek(-1, 1)
      file.write(bytes([byte[0] ^ 1]))
    run('damaged-data', value, expected=1)

    source, value = records[0]
    unicode_path = work / '\u6837\u672c data.bin'
    shutil.copyfile(source, unicode_path)
    parts = value.split('*')
    parts[8] = str(unicode_path).encode('utf-8').hex()
    run('unicode-path', '*'.join(parts))

    with source.open('r+b') as file:
      file.truncate(512)
    run('truncated-source', value, expected=None, show=True)

  print('%d streaming reference checks passed.' % checks)


if __name__ == '__main__':
  main()
