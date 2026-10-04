#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

# AS/400 DES: the EBCDIC user name is DES encrypted under a key derived from the EBCDIC password,
# each password byte xored with 0x55 and shifted left one bit. Convert::EBCDIC's table is Python's
# cp037. Name and password are space padded to 8 bytes.


def _ebcdic(s):
  return s.decode("latin-1").encode("cp037")


def as400_des(username, password):
  username = (username + b" " * 8)[:8]
  password = (password + b" " * 8)[:8]

  username_ebc = _ebcdic(username)
  password_ebc = _ebcdic(password)

  key = bytes(((b ^ 0x55) << 1) & 0xff for b in password_ebc)

  ciphertext = DES.new(key, DES.MODE_ECB).encrypt(username_ebc)

  return ciphertext.hex()


def module_constraints():
  return [[0, 8], [1, 8], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  hash_buf = as400_des(salt.upper().encode("latin-1"), word)

  return "$as400$des$*%s*%s" % (salt.upper(), hash_buf.upper())


def module_verify_hash(line):
  elements = line.split(b":")

  if len(elements) < 2:
    return None

  hash_in = elements[0].decode(errors="replace")

  word = b":".join(elements[1:])

  fields = hash_in.split("*")

  if fields[0] != "$as400$des$":
    return None

  salt = fields[1]

  return (module_generate_hash(word, salt), word)
