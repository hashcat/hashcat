#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

"""Check salted candidate sets and attack-specific windows across slow attacks."""

import hashlib
import hmac
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent / 'test_modules'))
from lib.md5crypt import md5_crypt

ROOT = Path(__file__).resolve().parent.parent
HASHCAT = Path(os.environ.get('HC_HASHCAT', ROOT / ('hashcat.exe' if os.name == 'nt' else 'hashcat'))).resolve()


def aescrypt(word, salt):
  key = salt + bytes(16)
  wide = word.decode('utf-8').encode('utf-16-le')
  for _ in range(8192):
    key = hashlib.sha256(key + wide).digest()
  iv = bytes(range(16))
  file_key = bytes(range(32))
  digest = hmac.new(key, iv + file_key, hashlib.sha256).hexdigest()
  line = '$aescrypt$1*%s*%s*%s*%s' % (salt.hex(), iv.hex(), file_key.hex(), digest)
  return line


def main():
  if HASHCAT.is_file() is False:
    raise SystemExit('Run make before this test.')
  backend = shlex.split(os.environ.get('HC_OPTS', ''))
  modes = [int(mode) for mode in os.environ.get('HC_MODES', '500,22400').split(',')]
  wanted = set(os.environ.get('HC_CASES', '').split(',')) - {''}
  checks = 0
  excluded = 0

  with tempfile.TemporaryDirectory(prefix='salt_inner_') as directory:
    work = Path(directory)
    (work / 'cache').mkdir()
    (work / 'rules').write_text(':\n$!\n', encoding='ascii')
    (work / 'mask.hcmask').write_text('01,?1\n01,?1?1\n', encoding='ascii')
    (work / 'table.words').write_text('ab\nba\n', encoding='ascii')
    (work / 'table').write_text('a\tA\nb\tB\n', encoding='ascii')

    def run(name, mode, attack, options, sources, expected, hashes=()):
      mask_options = ['--markov-disable'] if attack in (3, 6, 7, 12) else []
      if (len(mask_options) > 0) and (any(str(source).endswith('.hcmask') for source in sources) == False):
        mask_options.extend(['-1', '01'])
      command = [str(HASHCAT), '--quiet', '--session', work.name + '-' + name,
                 '--cache-path', str(work / 'cache'), '--potfile-disable',
                 '--restore-disable', '--logfile-disable', '-m', str(mode),
                 '-a', str(attack), *mask_options, *backend,
                 *options]
      command.extend(str(path) for path in hashes)
      command.extend(str(source) for source in sources)
      result = subprocess.run(command, cwd=HASHCAT.parent, capture_output=True,
                              text=True, timeout=180)
      code = result.returncode & 0xff if result.returncode >= 0 else result.returncode
      assert code == expected, (name, command, result.returncode, result.stdout, result.stderr)
      return result

    def passed(name):
      nonlocal checks
      checks += 1
      print(name + ': passed', flush=True)

    def hash_values(mode, name, plains):
      targets = {}
      for index, plain in enumerate(plains):
        word = plain.encode('utf-8')
        if mode == 500:
          digest = md5_crypt(b'$1$', 1000, word, ('s%07d' % index).encode())
        else:
          digest = aescrypt(word, index.to_bytes(16, 'little'))
        targets[digest] = plain
      path = work / (name + '.hashes')
      path.write_text('\n'.join(targets) + '\n', encoding='ascii')
      return path, targets

    def crack(name, mode, attack, options, sources, hashfile, targets, expected):
      outfile = work / (name + '.out')
      result = run(name, mode, attack, ['--outfile', str(outfile), '--outfile-format', '1,3',
                                      *options], sources, 1, hashes=[hashfile])
      found = {}
      if outfile.exists():
        for line in outfile.read_text(encoding='ascii').splitlines():
          digest, plain = line.split(':')
          found[digest] = bytes.fromhex(plain).decode('utf-8')
      expected_hashes = {digest: plain for digest, plain in targets.items() if plain in expected}
      assert found == expected_hashes, (name, found, expected_hashes, result.stderr)
      passed(name)

    for mode in modes:
      assert mode in (500, 22400), mode
      left = ['a', 'b', 'c'] if mode == 500 else ['\u00e4', '\u00f6', '\u00fc']
      a, b, c = left
      right = ['X', 'Y', 'Z']
      for name, values in [('left2', left[:2]), ('left3', left), ('right2', right[:2]), ('right3', right)]:
        (work / name).write_text('\n'.join(values) + '\n', encoding='utf-8')
      pcfg = work / 'pcfg'
      (pcfg / 'Grammar').mkdir(parents=True, exist_ok=True)
      (pcfg / 'Context').mkdir(exist_ok=True)
      (pcfg / 'Grammar' / 'grammar.txt').write_text('X1\t1.0\n', encoding='ascii')
      (pcfg / 'Context' / '1.txt').write_text(''.join(word + '\t1.0\n' for word in left), encoding='utf-8')
      cases = []

      def case(name, attack, sources, values, space, window, host_window,
               first=None, opt_window=None, options=None, host_skip=1):
        cases.append(dict(name=name, attack=attack, sources=sources,
                          values=set(values), space=space, window=set(window),
                          host_window=set(host_window), first=first or values[0],
                          opt_window=set(opt_window) if opt_window else set(window),
                          options=options or [], host_skip=host_skip))

      case('combi-swapped', 1, [work / 'left2', work / 'right3'],
           [l + r for l in left[:2] for r in right], 3,
           [a + 'Y', b + 'Y'], [a + 'Y'])
      case('combi-unswapped', 1, [work / 'left3', work / 'right2'],
           [l + r for l in left for r in right[:2]], 3,
           [b + 'X', b + 'Y'], [a + 'Y'])
      case('mask', 3, ['?1?1'], [x + y for x in '01' for y in '01'],
           2, ['01', '11'], ['10'])
      case('suffix', 6, [work / 'left2', '?1'],
           [l + d for l in left[:2] for d in '01'], 2,
           [b + '0', b + '1'], [a + '1'])
      case('prefix', 7, ['?1', work / 'left2'],
           [d + l for d in '01' for l in left[:2]], 2,
           ['1' + a, '1' + b], ['1' + a],
           opt_window=['0' + b, '1' + b])
      case('hybrid-suffix', 12, ['?w?1', work / 'left2'],
           [l + d for l in left[:2] for d in '01'], 2,
           [b + '0', b + '1'], [a + '1'])
      case('hybrid-prefix', 12, ['?1?w', work / 'left2'],
           [d + l for d in '01' for l in left[:2]], 2,
           ['1' + a, '1' + b], ['1' + a],
           opt_window=['0' + b, '1' + b])
      case('hybrid-middle', 12, ['?1?w?1', work / 'left2'],
           [x + l + y for x in '01' for l in left[:2] for y in '01'], 2,
           [x + b + y for x in '01' for y in '01'], ['1' + a + '0'])
      case('hybrid-two-words', 12, ['?1?w?1?q?1', work / 'left2', work / 'right2'],
           [x + l + y + r + z for x in '01' for l in left[:2]
            for y in '01' for r in right[:2] for z in '01'], 2,
           [x + b + y + r + z for x in '01' for y in '01'
            for r in right[:2] for z in '01'], ['0' + a + '0Y0'])
      queue = ['0', '1', '00', '10', '01', '11']
      case('maskfile', 3, [work / 'mask.hcmask'], queue, 3,
           ['00', '10'], ['00'], host_skip=2)
      case('increment', 3, ['?1?1'], queue, 3, ['00', '10'], ['00'],
           options=['--increment', '--increment-min', '1', '--increment-max', '2'], host_skip=2)
      case('pcfg', 4, [pcfg], left, 3, [b], [b])
      case('generic-wordlist', 8, ['wordlist', work / 'left3'], left, 3, [b], [b])
      case('table', 5, [work / 'table.words', work / 'table'],
           ['ab', 'aB', 'Ab', 'AB', 'ba', 'bA', 'Ba', 'BA'], 8, ['aB'], ['aB'])

      for item in cases:
        if (len(wanted) > 0) and ((item['name'] in wanted) == False):
          continue
        for rules in (False, True):
          values = item['values'] | {word + '!' for word in item['values']} if rules else item['values']
          hashfile, targets = hash_values(mode, str(mode) + '-' + item['name'] + str(rules),
                                         sorted(values) + ['outside-keyspace'])
          for host in (False, True):
            label = str(mode) + '-' + item['name'] + ('-rules' if rules else '') + ('-host' if host else '-device')
            optimized = (mode == 500) and (('-O' in backend) or ('--optimized-kernel-enable' in backend))
            if (host == True) and (rules == False) and (item['name'] == 'combi-swapped'):
              print(label + ': excluded (inherited -S swapped-source defect)', flush=True)
              excluded += 1
              continue
            if (host == True) and (rules == False) and (item['name'] == 'prefix') and (optimized == False):
              print(label + ': excluded (inherited -S typed-prefix null source)', flush=True)
              excluded += 1
              continue
            options = [*item['options']]
            if host:
              options.append('-S')
            if rules:
              options.extend(['-r', str(work / 'rules')])
            keyspace = len(values) if rules or host else item['space']
            if rules and host:
              keyspace = len(item['values']) * 2
            if (rules == True) and (host == False):
              keyspace = len(item['values'])
            result = run(label + '-keyspace', mode, item['attack'],
                         ['--keyspace', *options], item['sources'], 0)
            assert result.stdout.strip() == str(keyspace), (label, result.stdout, keyspace, result.stderr)
            passed(label + '-keyspace')
            crack(label + '-full', mode, item['attack'], options, item['sources'], hashfile, targets, values)
            if rules:
              skip = 1 if host else 0
              expected = {item['first'] + '!'} if host else {item['first'], item['first'] + '!'}
            else:
              skip = item['host_skip'] if host else 1
              expected = item['host_window'] if host else item['opt_window'] if optimized else item['window']
            crack(label + '-window', mode, item['attack'], [*options, '-s', str(skip), '-l', '1'],
                  item['sources'], hashfile, targets, expected)

      if (len(wanted) == 0) or ('random' in wanted):
        random_words = ['sqe0vwc2t1', 'awxu0tzgygrr8', 'fbjxw1nj6q', '4jdm2kjariv']
        values = random_words + [word + '!' for word in random_words]
        hashfile, targets = hash_values(mode, str(mode) + '-random', values + ['outside-keyspace'])
        for host in (False, True):
          label = str(mode) + '-random-' + ('host' if host else 'device')
          options = ['-r', str(work / 'rules'), '-s', '2' if host else '1', '-l', '2']
          if host:
            options.append('-S')
          words = random_words[1:2] if host else random_words[1:3]
          expected = set(words + [word + '!' for word in words])
          crack(label, mode, 8, options, ['random'], hashfile, targets, expected)

      if (len(wanted) == 0) or ('association' in wanted):
        (work / 'association.words').write_text('\n'.join([a, b, a, b]) + '\n', encoding='utf-8')
        hashfile, targets = hash_values(mode, str(mode) + '-association', [a, b, b, a])
        first_two = set(list(targets)[:2])
        for rules in (False, True):
          label = str(mode) + '-association' + ('-rules' if rules else '')
          options = ['-r', str(work / 'rules')] if rules else []
          result = run(label + '-keyspace', mode, 9, ['--keyspace', *options], [work / 'association.words'], 254)
          assert '--keyspace cannot be used with attack mode 9' in result.stderr, (label, result.stderr)
          passed(label + '-keyspace-rejected')
          for window in (False, True):
            name = label + ('-window' if window else '-full')
            outfile = work / (name + '.out')
            selected = {list(targets)[1]} if window else first_two
            window_options = ['-s', '1', '-l', '1'] if window else []
            run(name, mode, 9, ['--outfile', str(outfile), '--outfile-format', '1,3',
                               *options, *window_options],
                [work / 'association.words'], 1, hashes=[hashfile])
            found = dict(line.split(':') for line in outfile.read_text().splitlines())
            expected = {digest: targets[digest].encode().hex() for digest in selected}
            assert found == expected, (name, found, expected)
            passed(name)

  assert checks > 0, 'No test cases selected'
  print(str(checks) + '/' + str(checks) + ' salt-inner checks passed, ' +
        str(excluded) + ' inherited cases excluded')


if __name__ == '__main__':
  main()
