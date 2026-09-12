#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##
## Build a hint ruleset out of a trained PCFG ruleset.
##
## A hint ruleset keeps everything the trained ruleset records about what people put around a word, and
## discards everything it records about the word itself, because the words are supplied rather than
## guessed. hashcat ships the result of running this over the default ruleset as pcfg/hints.tar.xz.
##
## Two things change. Every letter run becomes one hint token, H1, whatever length the run had, and the
## probabilities of the structures that collapse together are added. The capitalization masks, which are
## one file per length in a trained ruleset, become one flat file of three masks that work at any length.
##
## Usage: pcfg_hints.py <trained ruleset> <output directory>
##
## The trained ruleset may be a directory or a .tar.xz. The output is a directory; pack it yourself.
##

import os
import re
import sys
import shutil
import tarfile
import tempfile
import collections
from typing import Dict, List, Optional, Tuple

# Which directory a token type reads, in the trained ruleset. This is the same table feed_pcfg.c keeps
# in type_dir(), and the two have to agree or a ruleset written here will not load.

TYPE_DIR = {
  'A': 'Alpha',
  'C': 'Capitalization',
  'D': 'Digits',
  'O': 'Other',
  'K': 'Keyboard',
  'X': 'Context',
  'Y': 'Years',
}

# The types carried over unchanged. Alpha goes because the hint replaces it, and Capitalization goes
# because it is rewritten.

CARRY = ['Digits', 'Other', 'Keyboard', 'Context', 'Years']

# The three masks a hint gets, and what they are worth.
#
# A mask is applied left to right and stops at the shorter of the mask and the token, and a position the
# mask does not name is left as the terminal stored it. So a one character mask constrains the first
# character and leaves the rest alone, which is what makes these work at any length. The long run
# of U is as long as a candidate can be.
#
# The weights are the trained masks summed by class, each length weighted by how much letter run mass the
# grammar puts at that length. The classes that depend on where the word ends are dropped: uppercasing
# the last character is 1.33 per cent of the mass and has no length agnostic spelling.
#
# They are the numbers that fall out of default-passwords, written down rather than worked out again per
# input, so a ruleset trained on something else carries them too. Three numbers taken off one large
# English corpus are close enough for a mask list this short, and the shipped pcfg/hints.tar.xz has to
# stay reproducible from the shipped pcfg/default-passwords.tar.xz, which is what pins them here.

HINT_MASKS = [
  ('L' * 1,  0.8520),
  ('U' * 1,  0.0901),
  ('U' * 64, 0.0245),
]

TOKEN = re.compile(r'([A-Z])(\d+)')

def read_prob_file(path: str) -> List[Tuple[str, float]]:
  out: List[Tuple[str, float]] = []

  with open(path, 'r', encoding='utf-8', errors='replace') as fp:
    for line in fp:
      line = line.rstrip('\n').rstrip('\r')

      if '\t' not in line:
        continue

      value, prob = line.split('\t', 1)

      try:
        p = float(prob)
      except ValueError:
        continue

      out.append((value, p))

  return out

def write_prob_file(path: str, rows: List[Tuple[str, float]]) -> None:
  os.makedirs(os.path.dirname(path), exist_ok=True)

  with open(path, 'w', encoding='utf-8') as fp:
    for value, p in rows:
      fp.write("%s\t%.17g\n" % (value, p))

# Turn one structure into its hint shape, or None when it has no letter run at all.
#
# A structure with no letter run carries none of the supplied words, and the OMEN escape M generates a
# whole password from a Markov model with no word in it, so neither belongs in a hint ruleset.

def collapse_structure(struct: str) -> Optional[str]:
  if struct == 'M':
    return None

  parts = TOKEN.findall(struct)

  if len(parts) == 0:
    return None

  if any(t == 'A' for t, n in parts) is False:
    return None

  return ''.join(('H1' if t == 'A' else t + n) for t, n in parts)

def collapse_grammar(src: str) -> Tuple[List[Tuple[str, float]], Dict[str, int], float]:
  rows = read_prob_file(os.path.join(src, 'Grammar', 'grammar.txt'))

  mass: Dict[str, float] = collections.defaultdict(float)
  came: Dict[str, int] = collections.Counter()

  kept = 0.0

  for struct, p in rows:
    shape = collapse_structure(struct)

    if shape is None:
      continue

    mass[shape] += p
    came[shape] += 1

    kept += p

  # Renormalise over what is left. A cost is a rounded bit count of a probability, so leaving the mass
  # short would push every cost up by the same amount and change only the numbers a report
  # prints. Renormalising keeps them comparable with the ruleset this came from.

  out = [(shape, p / kept) for shape, p in mass.items()]

  out.sort(key=lambda row: (-row[1], row[0]))

  return out, came, kept

def carry_lists(src: str, dst: str) -> int:
  files = 0

  for name in CARRY:
    src_dir = os.path.join(src, name)

    if os.path.isdir(src_dir) is False:
      continue

    dst_dir = os.path.join(dst, name)

    os.makedirs(dst_dir, exist_ok=True)

    for entry in sorted(os.listdir(src_dir)):
      if entry.endswith('.txt') is False:
        continue

      shutil.copyfile(os.path.join(src_dir, entry), os.path.join(dst_dir, entry))

      files += 1

  return files

def write_hint_masks(dst: str) -> None:
  total = sum(p for _, p in HINT_MASKS)

  rows = [(mask, p / total) for mask, p in HINT_MASKS]

  write_prob_file(os.path.join(dst, 'Capitalization', '1.txt'), rows)

# A trained ruleset may be a directory or one .tar.xz holding a single top level directory. Unpack the
# archive into a temporary directory and hand back the ruleset root inside it.

def open_ruleset(path: str, tmp: str) -> str:
  if os.path.isdir(path) is True:
    return path

  with tarfile.open(path, 'r:xz') as tf:
    # Python 3.12 requires a filter saying how much of a member's metadata to trust, and older ones do
    # not accept the argument at all. "data" is the strict filter and is what a ruleset needs: plain files
    # under one directory, no links, no devices, no absolute paths.

    try:
      tf.extractall(tmp, filter='data')
    except TypeError:
      tf.extractall(tmp)

  names = [e for e in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, e))]

  if len(names) != 1:
    raise RuntimeError("%s: expected one top level directory, found %d" % (path, len(names)))

  return os.path.join(tmp, names[0])

def main(argv: List[str]) -> int:
  if len(argv) != 3:
    sys.stderr.write("usage: %s <trained ruleset> <output directory>\n" % argv[0])

    return 1

  src_arg = argv[1]
  dst = argv[2]

  # The output is written into dst, and one file it writes is Grammar/grammar.txt. Named as the input
  # directory, that overwrites the grammar it is reading halfway through and leaves neither ruleset
  # usable.

  if os.path.isdir(src_arg) is True:
    if os.path.realpath(src_arg) == os.path.realpath(dst):
      sys.stderr.write("%s: the output directory is the input ruleset, which it would overwrite\n" % dst)

      return 1

  tmp = tempfile.mkdtemp(prefix='pcfg_hints.')

  try:
    src = open_ruleset(src_arg, tmp)

    if os.path.isfile(os.path.join(src, 'Grammar', 'grammar.txt')) is False:
      sys.stderr.write("%s: no Grammar/grammar.txt, this is not a ruleset\n" % src_arg)

      return 1

    shapes, came, kept = collapse_grammar(src)

    # Every shape a hint ruleset has is a structure with a letter run in it, so a grammar with none is
    # not something a hint ruleset can be made of. Writing an empty grammar and reporting success gives
    # a ruleset hashcat then refuses for having no structures, without reporting the cause.

    if len(shapes) == 0:
      sys.stderr.write("%s: no structure in this grammar has a letter run, so there is no hint to build one on\n" % src_arg)

      return 1

    write_prob_file(os.path.join(dst, 'Grammar', 'grammar.txt'), shapes)

    write_hint_masks(dst)

    files = carry_lists(src, dst)

    sys.stdout.write("shapes.....: %d\n" % len(shapes))
    sys.stdout.write("collapsed..: %d structures\n" % sum(came.values()))
    sys.stdout.write("mass kept..: %.4f of the trained grammar\n" % kept)
    sys.stdout.write("carried....: %d terminal files\n" % files)
    sys.stdout.write("written to.: %s\n" % dst)

    return 0

  finally:
    shutil.rmtree(tmp, ignore_errors=True)

if __name__ == '__main__':
  sys.exit(main(sys.argv))
