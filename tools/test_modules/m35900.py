#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import math

from lib.test_helpers import random_number, split_hash_word

# Hashids, written from the algorithm. The password is the Hashids salt, taken as bytes, and the line
# carries min_length, the alphabet as hex (empty for the default), the encoded numbers and the
# hashid. The encoder reproduces the vectors of hashids-python's own tests.
#
# Alphabets with ':' or '*' are left out here: test.py splits the hash from the word at the first
# ':', and '*' separates the fields of the line.

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
SEPARATORS = "cfhistuCFHISTU"

RATIO_SEPARATORS = 3.5
RATIO_GUARDS = 12


def reorder(chars: list, salt: str) -> list:
  out = list(chars)

  if len(salt) == 0:
    return out

  index = 0
  total = 0

  for i in range(len(out) - 1, 0, -1):
    c = ord(salt[index])

    total += c

    j = (c + index + total) % i

    out[i], out[j] = out[j], out[i]

    index = (index + 1) % len(salt)

  return out


def to_base(number: int, alphabet: list) -> str:
  out = ""

  while True:
    out = alphabet[number % len(alphabet)] + out

    number //= len(alphabet)

    if number == 0:
      return out


def setup(salt: str, alphabet_in: str):
  seen = []

  for c in alphabet_in:
    if c not in seen:
      seen.append(c)

  seps     = [c for c in SEPARATORS if c in alphabet_in]
  alphabet = [c for c in seen if c not in seps]

  seps = reorder(seps, salt)

  missing = math.ceil(len(alphabet) / RATIO_SEPARATORS) - len(seps)

  if missing > 0:
    seps     = seps + alphabet[:missing]
    alphabet = alphabet[missing:]

  alphabet = reorder(alphabet, salt)

  guards_cnt = math.ceil(len(alphabet) / RATIO_GUARDS)

  if len(alphabet) < 3:
    guards = seps[:guards_cnt]
    seps   = seps[guards_cnt:]
  else:
    guards   = alphabet[:guards_cnt]
    alphabet = alphabet[guards_cnt:]

  return alphabet, seps, guards


def encode(values: list, salt: str = "", min_length: int = 0, alphabet_in: str = ALPHABET) -> str:
  if len(values) == 0:
    return ""

  alphabet, seps, guards = setup(salt, alphabet_in)

  values_hash = 0

  for i, v in enumerate(values):
    values_hash += v % (i + 100)

  lottery = alphabet[values_hash % len(alphabet)]

  encoded = lottery

  for i, v in enumerate(values):
    alphabet_salt = (lottery + salt + "".join(alphabet))[:len(alphabet)]

    alphabet = reorder(alphabet, alphabet_salt)

    part = to_base(v, alphabet)

    encoded += part

    encoded += seps[(v % (ord(part[0]) + i)) % len(seps)]

  encoded = encoded[:-1]

  if len(encoded) >= min_length:
    return encoded

  encoded = guards[(values_hash + ord(encoded[0])) % len(guards)] + encoded

  if len(encoded) < min_length:
    encoded = encoded + guards[(values_hash + ord(encoded[2])) % len(guards)]

  half = len(alphabet) // 2

  while len(encoded) < min_length:
    alphabet = reorder(alphabet, "".join(alphabet))

    encoded = "".join(alphabet[half:]) + encoded + "".join(alphabet[:half])

    excess = len(encoded) - min_length

    if excess > 0:
      start = excess // 2

      encoded = encoded[start:start + min_length]

  return encoded


SIGNATURE = "$hashids$"

ALPHABETS = (
  "",
  "abcdefghijklmnopqrstuvwxyz",
  "ABcfhistuCFHISTU",
  "abdegjklmnopqrvwxyzABDEGJKLMNOPQRVWXYZ1234567890",
  "!\"#%&',-/0123456789;<=>ABCDEFGHIJKLMNOPQRSTUVWXYZ_`abcdefghijklmnopqrstuvwxyz~",
)


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': None,
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def make_line(word, min_length, alphabet_field, values):
  alphabet = ALPHABET if alphabet_field == "" else alphabet_field

  hashid = encode(values, word.decode("latin-1"), min_length, alphabet)

  line = "%s%u*%s*%s*%s" % (SIGNATURE, min_length, alphabet_field.encode("latin-1").hex(), ",".join(str(v) for v in values), hashid)

  return line


def module_generate_hash(word, salt, min_length=None, alphabet_field=None, values=None):
  if alphabet_field is None:
    alphabet_field = ALPHABETS[random_number(0, len(ALPHABETS) - 1)]

  if min_length is None:
    min_length = 0 if random_number(0, 1) == 0 else random_number(1, 40)

  if values is None:
    values = []

    for _ in range(random_number(1, 4)):
      if random_number(0, 3) == 0:
        values.append(random_number(0, (1 << 63) - 1))
      else:
        values.append(random_number(0, 1000000))

  line = make_line(word, min_length, alphabet_field, values)

  # A hashid is at most 128 characters on the module's side. An alphabet that leaves 2 symbols writes
  # a 64 bit number in 64 of them, so large numbers there are brought down to fit.

  if len(line.split("*")[-1]) > 128:
    line = make_line(word, min_length, alphabet_field, [v % 1000000 for v in values])

  return line


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  if hash_in[:len(SIGNATURE)] != SIGNATURE:
    return None

  fields = hash_in[len(SIGNATURE):].split("*")

  if len(fields) != 4:
    return None

  min_length, alphabet_hex, values, hashid = fields

  alphabet_field = bytes.fromhex(alphabet_hex).decode("latin-1")

  line_out = make_line(word, int(min_length), alphabet_field, [int(v) for v in values.split(",")])

  return (line_out, word)
