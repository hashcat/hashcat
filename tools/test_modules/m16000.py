#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib import libcrypt

# Tripcode: DES crypt of the Shift JIS password, with a salt made from its second and third
# character, and the last ten characters of the result.

SALT_FROM = ":;<=>?@[\\]^_`"
SALT_TO   = "ABCDEFGabcdef"


def module_test_properties():
  # Declare input bounds and optional iteration defaults and CI timings for the test tools.
  return {
    'constraints': {
      'pure': {
        'password_length': [1, 8],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None, iterations=None):
  word = word.decode("latin-1").encode("shift_jis", errors="replace")

  salt = (word + b"..")[1:3].decode("latin-1")

  salt = "".join(c if "." <= c <= "z" else "." for c in salt)

  salt = salt.translate(str.maketrans(SALT_FROM, SALT_TO))

  return libcrypt.crypt(word.decode("latin-1"), salt)[-10:]


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 1:
    return None

  word = line[idx + 1:]

  return (module_generate_hash(word), word)
