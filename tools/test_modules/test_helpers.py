#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What tools/test.py gives a test module. tools/test.pl hands its own subs to a .pm for free,
# because require loads them into the same namespace; here a module says what it wants.
#
# $HEX[...] is not here on purpose. test.py unwraps it before a module ever sees the line, so no
# module carries that call.

import random


def random_number(minimum, maximum):
  if minimum > maximum:
    return None

  return random.randint(minimum, maximum)


def random_numeric_string(count):
  return "".join(random.choice("0123456789") for _ in range(count))


def random_hex_string(count):
  return "".join(random.choice("0123456789abcdef") for _ in range(count))


def random_bytes(count):
  return bytes(random.randrange(256) for _ in range(count))
