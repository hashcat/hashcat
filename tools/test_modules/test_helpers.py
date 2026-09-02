#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# What tools/test.py gives a test module. tools/test.pl hands its own subs to a .pm for free,
# because require loads them into the same namespace, which is why m05200.pm can call
# pack_if_HEX_notation with nothing declaring it. Here a module says what it wants.

import random
import re

HEX_NOTATION = re.compile(rb"^\$HEX\[([0-9a-fA-F]*)\]$")


def pack_if_HEX_notation(word):
    # hashcat writes a password it cannot print as $HEX[...]. Give back the bytes it stands for.
    # Call this as soon as a password has been parsed out of a crack line, or the tests fail on
    # every password hashcat chose to escape.

    match = HEX_NOTATION.match(word)

    if match is None:
        return word

    return bytes.fromhex(match.group(1).decode("ascii"))


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
