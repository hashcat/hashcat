#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The python counterpart to tools/test.pl. Same idea: load the module for one hash mode at run
# time and call the hooks it defines. tools/test.sh reaches it with -y.
#
# A module deals in bytes for the password and str for everything else. A password really is an
# arbitrary byte string: it carries multi byte UTF-8, and once $HEX[...] is unwrapped it can be
# bytes that are not text at all. A hash and a salt are text. The password is never interpolated
# into source, a command line or a format string, so a quote, a dollar or a percent in it means
# nothing anywhere on the path.

import importlib
import os
import random
import re
import sys

TDIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(TDIR, "test_modules"))

from test_helpers import random_number, random_numeric_string  # noqa: E402

SINGLE_OUTPUTS = 8
GIVEUP_AT      = 1000000

# test.sh exports IS_OPTIMIZED from the same value it uses to decide on -O. Unset means optimized,
# which is what running tools/test.pl by hand does too.

IS_OPTIMIZED = os.environ.get("IS_OPTIMIZED", "1") != "0"



# hashcat writes a password it cannot print as $HEX[...]. It is the password, and the password is
# the last field of a crack line, so the engine can unwrap it without knowing any module's hash
# format. Doing it here rather than in every module is a deliberate break from the .pm layout,
# where 490 of the 511 modules carry a pack_if_HEX_notation call and 21 do not, which is a
# per module detail nobody can keep right by hand.

HEX_NOTATION = re.compile(rb"\$HEX\[([0-9a-fA-F]*)\]$")


def unhexify(line):
  match = HEX_NOTATION.search(line)

  if match is None:
    return line

  return line[:match.start()] + bytes.fromhex(match.group(1).decode("ascii"))


def usage_exit():
  name = os.path.basename(sys.argv[0])

  sys.stderr.write(
    "\nUsage:\n"
    " {0} single      <mode> [length]\n"
    " {0} passthrough <mode> [iter]\n"
    " {0} potthrough  <mode> [iter]\n"
    " {0} verify      <mode> <hashfile> <cracksfile> <outfile>\n"
    "\n"
    "edge and password are not implemented in test.py yet, use tools/test.pl.\n"
    "\n".format(name))

  sys.exit(1)


def load_module(mode):
  name = "m%05d" % mode

  try:
    return importlib.import_module(name)
  except Exception as exc:
    sys.exit("Could not load test module: %s.py\n%s" % (name, exc))


def constraints(mod):
  # No substitution in either direction. A mode that has no kernel for the family the run asked
  # for is not applicable and says so, and test.sh turns exit 2 into a Skip. test.pl instead
  # copies the constraints across and rewrites IS_OPTIMIZED to match, so a -O run on a mode with
  # no optimized kernel silently reports on the pure one.
  #
  # Applicability is decided by the word pairs, slots 0 and 2. Slots 1 and 3 are the salt, where
  # [-1, -1] keeps its own meaning of "this mode has no salt".

  pairs = mod.module_constraints()

  word = list(pairs[2] if IS_OPTIMIZED else pairs[0])
  salt = list(pairs[3] if IS_OPTIMIZED else pairs[1])
  comb = list(pairs[4])

  if word[0] == -1 and word[1] == -1:
    sys.stderr.write("no %s kernel for this mode\n" % ("optimized" if IS_OPTIMIZED else "pure"))

    sys.exit(2)

  return word, salt, comb


def length_pool(len_min, len_max, descending):
  # The lengths a run of test vectors uses. Slots 0 and 1 are pinned to the edges so those are
  # always covered, the rest come off a shuffled pool, and a short range is padded by
  # duplicating an element.
  #
  # The sort is test.pl's: by digit count rather than by value, so both engines pick the same
  # shape. It leaves lengths above 9 unordered, which is a question for test.pl rather than
  # something to diverge on here.

  if len_min == -1 or len_max == -1:
    return None

  pool = [n for n in range(len_min, len_max + 1) if n != 0] or [len_min]

  while len(pool) < SINGLE_OUTPUTS:
    random.shuffle(pool)

    pool.append(pool[0])

  random.shuffle(pool)

  out = [len_min, len_max] + pool[:SINGLE_OUTPUTS - 2]

  out.sort(key=lambda n: len(str(n)), reverse=descending)

  return out


def word_lengths(word, salt, comb):
  len_min, len_max = word

  if IS_OPTIMIZED:
    if comb[0] != -1 and salt[0] == salt[1] and salt[0] != -1:
      len_max -= salt[0]

    if len_min != len_max:
      len_max = min(len_max, 31)

    len_min = min(len_min, len_max)

  return length_pool(len_min, len_max, False)


def salt_lengths(salt):
  len_min, len_max = salt

  if IS_OPTIMIZED and len_min != -1:
    len_max = min(len_max, 51)
    len_min = min(len_min, len_max)

  return length_pool(len_min, len_max, True)


def make_word(mod, count):
  word = random_numeric_string(count).encode("ascii")

  if hasattr(mod, "module_get_random_password"):
    word = mod.module_get_random_password(word)

  return word


def single(mod, mode, length):
  word, salt, comb = constraints(mod)

  db_word = word_lengths(word, salt, comb)
  db_salt = salt_lengths(salt)

  seen  = set()
  pairs = []

  giveup = 0

  while len(pairs) < SINGLE_OUTPUTS and giveup < GIVEUP_AT:
    giveup += 1

    if length is None:
      word_len = db_word[len(pairs)]
    else:
      if length < word[0] or length > word[1]:
        break

      word_len = length

    salt_len = 0

    if salt[0] != -1:
      salt_len = salt[0] if salt[0] == salt[1] else db_salt[giveup % len(db_salt)]

    if IS_OPTIMIZED and comb[0] != -1:
      if not comb[0] <= word_len + salt_len <= comb[1]:
        continue

    candidate = (make_word(mod, word_len), random_numeric_string(salt_len))

    if candidate in seen:
      continue

    seen.add(candidate)
    pairs.append(candidate)

  for word_bytes, salt_str in sorted(pairs, key=lambda p: len(p[0])):
    digest = mod.module_generate_hash(word_bytes, salt_str, None)

    # possible if the requested length is not supported by the algorithm

    if digest is None:
      continue

    sys.stdout.buffer.write(b"echo %-31s | ./hashcat ${OPTS} -a 0 -m %d '%s'\n"
                % (word_bytes, mode, digest.encode("utf-8")))


def passthrough(mod, iterations, with_plain):
  word, salt, comb = constraints(mod)

  for raw in sys.stdin.buffer:
    word_bytes = raw.rstrip(b"\r\n")

    if IS_OPTIMIZED and len(word_bytes) > 31:
      continue

    salt_len = 0

    if salt[0] != -1:
      salt_len = salt[0] if salt[0] == salt[1] else random_number(salt[0], salt[1])

    if IS_OPTIMIZED and comb[0] != -1:
      if not comb[0] <= len(word_bytes) + salt_len <= comb[1]:
        continue

    digest = mod.module_generate_hash(word_bytes, random_numeric_string(salt_len), iterations)

    if digest is None:
      continue

    line = digest.encode("utf-8")

    if with_plain:
      line += b":" + word_bytes

    sys.stdout.buffer.write(line + b"\n")



def verify(mod, hashes_file, cracks_file, out_file):
  with open(hashes_file, "rb") as handle:
    hashlist = set(line.rstrip(b"\r\n") for line in handle)

  with open(cracks_file, "rb") as handle, open(out_file, "wb") as out:
    for raw in handle:
      raw = raw.rstrip(b"\r\n")

      # the module is handed a line whose password is already the bytes it stands for

      line = unhexify(raw)

      parsed = mod.module_verify_hash(line)

      # possible if the hash:password pair does not match

      if parsed is None:
        continue

      digest, word = parsed

      if line != digest.encode("utf-8") + b":" + word:
        continue

      # possible if the hash is in the cracks file but not in the hash file

      if digest.encode("utf-8") not in hashlist:
        continue

      out.write(raw + b"\n")


def main():
  argv = sys.argv[1:]

  if len(argv) < 2:
    usage_exit()

  kind, mode = argv[0], argv[1]

  if kind in ("edge", "password"):
    sys.exit("%s is not implemented in test.py yet, use tools/test.pl\n" % kind)

  if kind not in ("single", "passthrough", "potthrough", "verify"):
    usage_exit()

  if not mode.isdigit():
    sys.exit("Mode must be a number\n")

  mode = int(mode)
  mod  = load_module(mode)

  for hook in ("module_constraints", "module_generate_hash", "module_verify_hash"):
    if not hasattr(mod, hook):
      sys.exit("Module function '%s' not found\n" % hook)

  if kind == "verify":
    if len(argv) != 5:
      usage_exit()

    verify(mod, argv[2], argv[3], argv[4])

    return

  extra = argv[2] if len(argv) > 2 else None

  if kind == "single":
    single(mod, mode, int(extra) if extra is not None and extra.isdigit() else None)
  else:
    passthrough(mod, int(extra) if extra is not None and extra.isdigit() else None,
          kind == "potthrough")


main()
