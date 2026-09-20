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

import random

HEX_CHARS       = "0123456789abcdef"
NUMERIC_CHARS   = "0123456789"
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MIXEDCASE_CHARS = UPPERCASE_CHARS + LOWERCASE_CHARS
STRING_CHARS    = UPPERCASE_CHARS + LOWERCASE_CHARS + NUMERIC_CHARS


def _pick(chars, count):
  return "".join(random.choice(chars) for _ in range(count))


def random_count(maximum):
  # 1 to maximum, the way test_module_runner.pl draws a count

  if maximum < 1:
    return None

  return random.randint(1, maximum)


def random_number(minimum, maximum):
  if minimum > maximum:
    return None

  return random.randint(minimum, maximum)


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
