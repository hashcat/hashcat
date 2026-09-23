#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What tools/test_module_runner.py gives a test module. tools/test_module_runner.pl hands its own subs to a .pm
# for free, because require loads them into the same namespace; here a module says what it wants.
#
# $HEX[...] is not here on purpose. test_module_runner.py unwraps it before a module ever sees the
# line, so no module carries that call.
#
# Every helper here draws through _rand (), which is either python's own generator or, when
# HCTEST_SEED is set, the same arithmetic tools/test_module_runner.pl uses under that variable.
# Seeded, the two engines draw the same characters in the same order, which is what lets
# tools/test_engine_compare.py hand a mode to both and compare what comes back.

import os
import random

HEX_CHARS       = "0123456789abcdef"
NUMERIC_CHARS   = "0123456789"
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MIXEDCASE_CHARS = UPPERCASE_CHARS + LOWERCASE_CHARS
STRING_CHARS    = UPPERCASE_CHARS + LOWERCASE_CHARS + NUMERIC_CHARS

_STATE = None


def seed(value):
  # The mix is what the perl engine does with HCTEST_SEED, so that the same number means the same
  # stream on both sides.

  global _STATE

  _STATE = (value * 2654435761) % 4294967291


def _rand(n=1.0):
  global _STATE

  if _STATE is None:
    return random.random() * n

  _STATE = ((_STATE * 1103515245) + 12345) % 2147483648

  return (_STATE / 2147483648) * n


def _pick(chars, count):
  return "".join(chars[int(_rand(len(chars)))] for _ in range(count))


if os.environ.get("HCTEST_SEED"):
  seed(int(os.environ["HCTEST_SEED"]))


def random_count(maximum):
  # 1 to maximum, the way test_module_runner.pl draws a count

  if maximum < 1:
    return None

  return int(_rand(maximum - 1)) + 1


def random_number(minimum, maximum):
  if minimum > maximum:
    return None

  return int(_rand((maximum + 1) - minimum)) + minimum


def random_string(count):
  return _pick(STRING_CHARS, count)


def random_lowercase_string(count):
  return _pick(LOWERCASE_CHARS, count)


def random_uppercase_string(count):
  return _pick(UPPERCASE_CHARS, count)


def random_mixedcase_string(count):
  return _pick(MIXEDCASE_CHARS, count)


def random_numeric_string(count):
  return _pick(NUMERIC_CHARS, count)


def random_hex_string(count):
  return _pick(HEX_CHARS, count)


def random_bytes(count):
  # the perl engine builds these out of a hex string of twice the length, so drawing them any other
  # way would take the two engines off the same stream

  return bytes.fromhex(random_hex_string(2 * count))


# The kernels that need UTF-16 either decode the UTF-8 or widen each byte, and a mode whose two
# kernel families disagree follows the one test.sh is about to run: latin-1 reproduces the widening
# byte for byte, utf-8 is the decoding. test.sh exports IS_OPTIMIZED from the value it uses for -O.

def kernel_charset():
  return "utf-8" if os.environ.get("IS_OPTIMIZED") == "0" else "latin-1"


def utf16le(word, charset="utf-8"):
  # errors="replace" is what perl's decode () does with a byte that is not UTF-8

  return word.decode(charset, errors="replace").encode("utf-16-le")


def utf16be(word, charset="utf-8"):
  return word.decode(charset, errors="replace").encode("utf-16-be")


# The two line shapes most modules verify. The password is everything after the separator, colons
# and all, which is where a perl split (':') used to cut it short.

def split_hash_word(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  return (line[:idx].decode(errors="replace"), line[idx + 1:])


def split_hash_salt_word(line):
  parts = line.split(b":", 2)

  if len(parts) != 3:
    return None

  return (parts[0].decode(errors="replace"), parts[1].decode(errors="replace"), parts[2])


def pack_hex(s):
  # perl's pack ("H*", s), for the modules that relied on what it does with input that is not hex:
  # a letter counts as its low 4 bits plus 9, anything else as its low 4 bits, and an odd length
  # leaves the last byte's low nibble zero. For a string of hex digits this is bytes.fromhex ().

  if isinstance(s, bytes):
    s = s.decode("latin-1")

  nibbles = [((ord(c) + 9) if ("A" <= c <= "Z" or "a" <= c <= "z") else ord(c)) & 0xf for c in s]

  if len(nibbles) % 2:
    nibbles.append(0)

  return bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
