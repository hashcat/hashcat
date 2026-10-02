#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import ARC4

from lib.test_helpers import random_number, random_string, split_hash_word

# RC4 40 bit with a partially known plaintext. The password is the 5 byte RC4 key. After dropping
# dropN keystream bytes the plaintext is encrypted; the hash keeps the ciphertext and the first 5
# bytes of the plaintext.


def module_constraints():
  return [[-1, -1], [-1, -1], [5, 5], [-1, -1], [-1, -1]]


def module_generate_hash(word, dropN=None, ciphertext=None, plaintext_offset=None, plaintext=None):
  if plaintext is None or dropN is None:
    dropN = random_number(0, 512)
    plaintext = random_string(random_number(5, 64)).encode("latin-1")

  drop_n = int(dropN)

  cipher = ARC4.new(word)

  if drop_n > 0:
    cipher.encrypt(b"\x00" * drop_n)

  digest = cipher.encrypt(plaintext).hex()

  if ciphertext is not None:
    if ciphertext[:10] == digest:
      digest = ciphertext

  return "$rc4$40$%d$%s$0$%s" % (drop_n, digest, plaintext.hex()[:10])


def module_verify_hash(line):
  res = split_hash_word(line)

  if res is None:
    return None

  hash_str, word = res

  if hash_str[:8] != "$rc4$40$":
    return None

  data = hash_str.split("$")

  if len(data) != 7:
    return None

  dropN = data[3]
  ciphertext = data[4]
  plaintext_offset = data[5]

  try:
    plaintext = bytes.fromhex(data[6])
  except ValueError:
    return None

  return (module_generate_hash(word, dropN, ciphertext, plaintext_offset, plaintext), word)
