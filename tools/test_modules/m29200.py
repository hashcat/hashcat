#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##
## Further credits:
## The password-storage algorithm used by Radmin 3 was analyzed and made public by synacktiv:
## https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html
##

import hashlib

from lib.test_helpers import kernel_charset, random_mixedcase_string, random_number

# Radmin 3. The verifier is g^e mod m, where e is a SHA1 chain over the UTF-16LE user and password.
# The optimized kernels widen each password byte instead of decoding the UTF-8, so the oracle picks
# latin-1 (widening) or utf-8 (decoding) from IS_OPTIMIZED the way test.sh does.

GENERATOR = "05"
MODULUS   = ("9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58"
             "cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947"
             "ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96"
             "db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79"
             "021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb"
             "0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d"
             "6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f19"
             "30ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f")


def module_constraints():
  return [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, user=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if user is None:
    user = random_mixedcase_string(random_number(0, 127)).encode("utf-16-le")

  word_utf16 = word.decode(kernel_charset(), errors="replace").encode("utf-16-le")

  inner = hashlib.sha1(user + b":" + word_utf16).digest()

  exponent = hashlib.sha1(salt + inner).hexdigest()

  pow_val = pow(int(GENERATOR, 16), int(exponent, 16), int(MODULUS, 16))

  res = pow_val.to_bytes((pow_val.bit_length() + 7) // 8, "big") if pow_val else b""

  res = b"\x00" * (256 - len(res)) + res

  return "$radmin3$%s*%s*%s" % (user.hex(), salt.hex(), res.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  if hash_in[0:9] != "$radmin3$":
    return None

  fields = hash_in[9:].split("*")

  if len(fields) != 3:
    return None

  user, salt, verifier = fields

  if len(salt) != 64:
    return None

  return (module_generate_hash(word, bytes.fromhex(salt), bytes.fromhex(user)), word)
