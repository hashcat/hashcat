#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The python counterpart to tools/test_module_runner.pl. Same idea: load the module for one hash mode at run
# time and call the hooks it defines. tools/test.sh reaches it for any mode that has a .py.
#
# A module deals in bytes for the password and str for everything else. A password really is an
# arbitrary byte string: it carries multi byte UTF-8, and once $HEX[...] is unwrapped it can be
# bytes that are not text at all. A hash and a salt are text. The password is never interpolated
# into source, a command line or a format string, so a quote, a dollar or a percent in it means
# nothing anywhere on the path.

import glob
import importlib
import os
import random
import re
import sys

TDIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.join(TDIR, "test_modules"))

from lib.test_helpers import random_number, random_numeric_string  # noqa: E402

SINGLE_OUTPUTS = 8
GIVEUP_AT      = 1000000

# test.sh exports IS_OPTIMIZED from the same value it uses to decide on -O. Unset means optimized,
# which is what running tools/test_module_runner.pl by hand does too.

IS_OPTIMIZED = os.environ.get("IS_OPTIMIZED", "1") != "0"

# Whether this mode may be handed a password that is not 7 bit ASCII. Decided once, after the
# module is loaded, because the answer depends on the module as well as on the mode.

NON_ASCII_OK = False

# The characters an edge case password is sprinkled with, and the rules for where they may land.
# These are tools/test_module_runner.pl's, because tools/test_edge.sh reads the two engines' output the same way:
# it rewrites the '?d' at a position whose byte is not a digit into that byte, so a mask can spell
# a character wherever it turns up, and the eight passwords of a length share one mask. That is why
# the layout below is seeded from the length rather than drawn at random.

NON_ASCII_CHARS = (
  b"\xe0\xa4\xb9",      # U+0939  devanagari letter ha
  b"\xe2\x82\xac",      # U+20AC  euro sign
  b"\xe3\x81\x8b",      # U+304B  hiragana letter ka
  b"\xe3\x82\xab",      # U+30AB  katakana letter ka
  b"\xe4\xb8\xad",      # U+4E2D  cjk ideograph 'middle'
  b"\xe6\x96\x87",      # U+6587  cjk ideograph 'script'
  b"\xe7\xa0\x81",      # U+7801  cjk ideograph 'code'
  b"\xe9\xbe\x8d",      # U+9F8D  cjk ideograph 'dragon'
  b"\xea\xb0\x80",      # U+AC00  hangul syllable ga
  b"\xef\xbc\xa1",      # U+FF21  fullwidth latin capital a
  b"\xf0\x9f\x98\x80",  # U+1F600 grinning face
)

NON_ASCII_SKIP_BYTES = 0
NON_ASCII_MIN_SPARE  = 1
NON_ASCII_RATE       = 0.34


def sprinkle_non_ascii(text):
  # Replace some of the digits with multi byte UTF-8 characters, in place, so the byte length of
  # the password does not change and it still fits whatever Pwd.Len.Max the mode declares. A
  # character is only ever written where a whole one fits and the scan then steps over it, so the
  # result is always valid UTF-8.

  data = bytearray(text.encode("ascii"))

  length = len(data)

  seed = (length * 2654435761) % 4294967291

  def rnd():
    nonlocal seed

    seed = (seed * 1103515245 + 12345) % 2147483648

    return seed / 2147483648

  pos = NON_ASCII_SKIP_BYTES

  while pos < length:
    char = NON_ASCII_CHARS[int(rnd() * len(NON_ASCII_CHARS))]

    char_len = len(char)

    spare = length - NON_ASCII_MIN_SPARE + (1 if pos > 0 else 0)

    if (pos + char_len) <= spare and rnd() < NON_ASCII_RATE:
      data[pos:pos + char_len] = char

      pos += char_len
    else:
      pos += 1

  return bytes(data)


def utf16_decoding_helpers():
  # Split the inc_hash_* conversion helpers into the ones that decode UTF-8 through hc_enc and the
  # ones that only widen the bytes. The scalar UTF-16LE variants decode; the vector ones, the HMAC
  # ones and every UTF-16BE variant do not.

  decoding = set()

  for inc in glob.glob(os.path.join(TDIR, "..", "OpenCL", "inc_hash_*.cl")):
    try:
      with open(inc, "r", errors="replace") as handle:
        src = handle.read()
    except OSError:
      continue

    for chunk in src.split("\nDECLSPEC "):
      match = re.match(r"\w[\w ]*?\s(\w+)\s*\(", chunk)

      if match is None:
        continue

      name = match.group(1)

      if "utf16" not in name:
        continue

      if "hc_enc_next" in chunk:
        decoding.add(name)

  return decoding


def non_ascii_supported(mode, mod):
  # Whether this mode can be handed a password that is not 7 bit ASCII. hashcat has no single flag
  # for it, so the module source is read for the option bits that pin the plaintext to a charset,
  # the same way tools/test.sh reads OPTS_TYPE_SUGGEST_KG and friends straight out of src/modules.

  if "NO_NON_ASCII" in os.environ:
    return False

  # a module that builds the password out of the generated string, a bitcoin seed or a NetNTLM
  # response for instance, needs that string in the format it expects

  if hasattr(mod, "module_get_random_password"):
    return False

  try:
    with open(os.path.join(TDIR, "..", "src", "modules", "module_%05d.c" % mode),
              "r", errors="replace") as handle:
      src = handle.read()
  except OSError:
    return False

  # OPTS_TYPE_PT_ALWAYS_ASCII says the plaintext is ASCII by definition, PT_LM and PT_UPPER case
  # fold it, which the kernels only do for ASCII, and PT_HEX, PT_BASE58 and PT_ALWAYS_HEXIFY spell
  # the password in an alphabet of their own.

  for opt in ("OPTS_TYPE_PT_ALWAYS_ASCII",
              "OPTS_TYPE_PT_ALWAYS_HEXIFY",
              "OPTS_TYPE_PT_BASE58",
              "OPTS_TYPE_PT_HEX",
              "OPTS_TYPE_PT_LM",
              "OPTS_TYPE_PT_LOWER",
              "OPTS_TYPE_PT_UPPER"):
    if opt in src:
      return False

  # A kernel that needs UTF-16 either decodes the UTF-8 with hc_enc or widens the bytes, and a
  # password above 0x7f only survives the first kind.

  decoding = utf16_decoding_helpers()

  any_utf16    = False
  pure_decodes = False

  for kernel in glob.glob(os.path.join(TDIR, "..", "OpenCL", "m%05d*.cl" % mode)):
    try:
      with open(kernel, "r", errors="replace") as handle:
        ksrc = handle.read()
    except OSError:
      continue

    decodes = re.search(r"\bhc_enc_next\s*\(", ksrc) is not None
    widens  = re.search(r"\bmake_utf16", ksrc) is not None

    if widens:
      any_utf16 = True

    for name in re.findall(r"\b(\w+_utf16\w*)\s*\(", ksrc):
      any_utf16 = True

      if name in decoding:
        decodes = True
      else:
        widens = True

    if kernel.endswith("-pure.cl"):
      pure_decodes = pure_decodes or decodes

  # nothing in this mode ever decodes, UTF-16BE for instance has no hc_enc path at all

  if any_utf16 and not pure_decodes:
    return False

  return True


def random_non_ascii_string(count, non_ascii_ok):
  # A password for a mode that can take one that is not 7 bit ASCII. Comes back as plain digits for
  # a mode that cannot take one, and for a password too short to hold one, so a caller gets a valid
  # password either way and never has to ask which.

  text = random_numeric_string(count)

  if non_ascii_ok is False:
    return text.encode("ascii")

  return sprinkle_non_ascii(text)



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
    " {0} edge        <mode> [attack-type] [optimized]\n"
    " {0} single      <mode> [length]\n"
    " {0} password    <mode> [length]\n"
    " {0} passthrough <mode> [iter]\n"
    " {0} potthrough  <mode> [iter]\n"
    " {0} verify      <mode> <hashfile> <cracksfile> <outfile>\n"
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
  # for is not applicable and says so, and test.sh turns exit 2 into a Skip. test_module_runner.pl instead
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
  # The sort is test_module_runner.pl's: by digit count rather than by value, so both engines pick the same
  # shape. It leaves lengths above 9 unordered, which is a question for test_module_runner.pl rather than
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
  word = random_non_ascii_string(count, NON_ASCII_OK)

  if hasattr(mod, "module_get_random_password"):
    word = mod.module_get_random_password(word)

  return word


def edge_constraints(mod, optimized):
  # tools/test_module_runner.pl copies one family's word and salt pairs over the other when a mode has a kernel
  # for only one of them, and edge keeps that rather than refusing the way constraints () does.
  # tools/test_edge.sh picks the family from hashcat's own Kernel.Type(s) instead of from the
  # module, and it counts an empty vector list as an error, so refusing here would report a mode
  # as broken for having nothing to say about a kernel it does not have.

  pairs = [list(pair) for pair in mod.module_constraints()]

  if pairs[0] == [-1, -1]:
    pairs[0] = list(pairs[2])
    pairs[1] = list(pairs[3])
  elif pairs[2] == [-1, -1]:
    pairs[2] = list(pairs[0])
    pairs[3] = list(pairs[1])

  word = pairs[2] if optimized else pairs[0]
  salt = pairs[3] if optimized else pairs[1]
  comb = pairs[4] if optimized else [-1, -1]

  return word, salt, comb


def edge_format(mod, mode, word_len, salt_len, attack_type, optimized, non_ascii_ok):
  while True:
    word = random_non_ascii_string(word_len, non_ascii_ok)
    salt = random_numeric_string(salt_len)

    if hasattr(mod, "module_get_random_password"):
      word = mod.module_get_random_password(word)

    digest = mod.module_generate_hash(word, salt)

    # m30901 answers with a hash of one length and nothing else is usable, so a short one is drawn
    # again rather than passed on

    if mode == 30901 and (digest is None or len(digest) != 34):
      continue

    break

  if digest is None:
    return

  # The word, the salt and the hash go out hex encoded. tools/test_edge.sh reads these fields into
  # shell variables, and a comma or a quote in one of them would otherwise end the field early or
  # unbalance the quoting around it. Hex contains neither, so a field stays separable whatever the
  # module puts in it, and the consumer decodes rather than parses.

  sys.stdout.write("%d,%d,%d,%d,%d,%s,%s,%s\n" % (
    mode, attack_type, 1 if optimized else 0, word_len, salt_len,
    word.hex(), salt.encode("ascii").hex(), digest.encode("utf-8").hex()))


def edge(mod, mode, attack_type, optimized):
  if attack_type not in (0, 1, 3, 4, 6, 7, 8, 9, 12):
    return -1

  word, salt, comb = edge_constraints(mod, optimized)

  word_min, word_max = word
  salt_min, salt_max = salt
  comb_max           = comb[1]

  non_ascii_ok = non_ascii_supported(mode, mod)

  if attack_type != 3 and optimized:
    if word_min != word_max and word_max > 31:
      word_max = 31

  # An attack that cuts the word in two needs a word with two halves. Attack types 0, 4, 8 and 9
  # hand the whole word to hashcat in one piece, so a one character word is a valid test for them.

  if attack_type not in (0, 4, 8, 9):
    word_min = max(word_min, 2)

  # Attack type 4 assembles its candidate out of grammar terminals and the shortest terminal is one
  # character long, so there is no way to hand it an empty word. A mode whose minimum is zero gets
  # a one character word for that corner instead, which is a case the attack can express.

  if attack_type == 4 and word_min == 0:
    word_min = 1

  def emit(word_len, salt_len):
    edge_format(mod, mode, word_len, salt_len, attack_type, optimized, non_ascii_ok)

  # word_min, salt_min / word_min, salt_max / word_max, salt_min / word_max, salt_max

  if word_min != -1:
    if salt_min != salt_max:
      if salt_min != -1:
        emit(word_min, salt_min)

      if salt_max != -1:
        salt_len = salt_max

        if optimized:
          salt_len = min(salt_len, 51)

          if comb_max != -1 and (word_min + salt_len) > comb_max:
            off = word_min + salt_len - comb_max

            if salt_len > off:
              salt_len -= off

        emit(word_min, salt_len)
    elif salt_min != -1:
      emit(word_min, salt_min)
    else:
      emit(word_min, 0)

  if word_max == -1:
    return 0

  if salt_min == salt_max:
    if salt_min == -1:
      emit(word_max, 0)

      return 0

    word_len = word_max
    salt_len = salt_max

    if optimized and comb_max != -1 and (word_len + salt_len) > comb_max:
      off = word_len + salt_len - comb_max

      if word_len > off:
        word_len = max(word_len - off, word_min)

    emit(word_len, salt_len)

    return 0

  last_word_len = -1

  if salt_min != -1:
    word_len = word_max
    salt_len = salt_min

    if optimized:
      comb_max_cur = comb_max if comb_max != -1 else 55

      if (word_len + salt_len) > comb_max_cur:
        off = word_len + salt_len - comb_max_cur

        if word_len <= off:
          sys.stdout.write("ERROR with MODE %d, WORD %d, SALT %d, MAX %d"
                           % (mode, word_len, salt_len, comb_max_cur))

          sys.exit(1)

        word_len -= off

    emit(word_len, salt_len)

    last_word_len = word_len

  if salt_max != -1:
    word_len = word_max
    salt_len = salt_max

    if optimized:
      comb_max_cur = comb_max if comb_max != -1 else 55

      salt_len = min(salt_len, 51)

      if (word_len + salt_len) > comb_max_cur:
        off = word_len + salt_len - comb_max_cur

        if last_word_len == word_len:
          word_len -= off

          if word_len < word_min:
            salt_len -= word_min - word_len
            word_len  = word_min
        else:
          salt_len -= off

          if salt_len < salt_min:
            word_len -= salt_min - salt_len
            salt_len  = salt_min

    emit(word_len, salt_len)

  return 0


def password(count):
  # One password for this mode, on stdout, nothing else. tools/test.sh builds its -g containers
  # with it, so a container gets the same multi byte characters the oracle passwords get, and the
  # same per mode gate decides whether it gets any.
  #
  # A real archive or volume carries whatever encoding the application wrote, and the optimized
  # path cannot match a multi byte one: a genuine 7-Zip archive built with a euro sign in its
  # password cracks under -P and comes back not found under -O. So a -O run has to build its
  # containers out of ASCII, and tools/test.sh sets NO_NON_ASCII to ask for that, which
  # non_ascii_supported () reads.

  sys.stdout.buffer.write(random_non_ascii_string(count, NON_ASCII_OK) + b"\n")


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

    # Check the module against itself before printing. module_verify_hash is what a consumer that
    # accepts submitted hashes calls to decide whether one is valid, so it is not test only
    # plumbing, and a hook nothing ever runs is a hook nobody knows is broken. Every vector the
    # suite generates now goes back through it.

    line = digest.encode("utf-8") + b":" + word_bytes

    checked = mod.module_verify_hash(line)

    if checked is None or checked[0].encode("utf-8") + b":" + checked[1] != line:
      sys.exit("module_verify_hash did not round trip module_generate_hash for mode %d\n  %r\n"
               % (mode, line))

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

  if kind not in ("edge", "single", "password", "passthrough", "potthrough", "verify"):
    usage_exit()

  if not mode.isdigit():
    sys.exit("Mode must be a number\n")

  mode = int(mode)

  # tools/test.sh exports IS_OPTIMIZED, but tools/test_edge.sh hands the same flag to the edge
  # subcommand as an argument instead. A module reads the variable when it is imported, so the
  # argument has to be in the environment before that happens.

  if kind == "edge" and len(argv) > 3 and argv[3] in ("0", "1"):
    global IS_OPTIMIZED

    os.environ["IS_OPTIMIZED"] = argv[3]

    IS_OPTIMIZED = argv[3] != "0"

  mod = load_module(mode)

  for hook in ("module_constraints", "module_generate_hash", "module_verify_hash"):
    if not hasattr(mod, hook):
      sys.exit("Module function '%s' not found\n" % hook)

  global NON_ASCII_OK

  NON_ASCII_OK = non_ascii_supported(mode, mod)

  if kind == "verify":
    if len(argv) != 5:
      usage_exit()

    verify(mod, argv[2], argv[3], argv[4])

    return

  if kind == "edge":
    attack_type = argv[2] if len(argv) > 2 else "0"
    optimized   = argv[3] if len(argv) > 3 else "0"

    if not attack_type.isdigit() or optimized not in ("0", "1"):
      usage_exit()

    sys.exit(0 if edge(mod, mode, int(attack_type), optimized == "1") == 0 else 1)

  extra = argv[2] if len(argv) > 2 else None

  if kind == "password":
    if len(argv) > 3:
      usage_exit()

    password(int(extra) if extra is not None and extra.isdigit() else 12)

    return

  if kind == "single":
    single(mod, mode, int(extra) if extra is not None and extra.isdigit() else None)
  else:
    passthrough(mod, int(extra) if extra is not None and extra.isdigit() else None,
          kind == "potthrough")


main()
