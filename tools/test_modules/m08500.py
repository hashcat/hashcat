#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

# RACF: the EBCDIC user name is DES encrypted under a key derived from the EBCDIC password, each
# password byte xored with 0x55 and shifted left one bit. Convert::EBCDIC's table is Python's cp037.


def _ebcdic(s):
  return s.decode("latin-1").encode("cp037")


def racf_hash(username, password):
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
  hash_buf = racf_hash(salt.upper().encode("latin-1"), word)

  return "$racf$*%s*%s" % (salt.upper(), hash_buf.upper())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  fields = hash_in.split("*")

  if len(fields) < 2 or fields[0] != "$racf$":
    return None

  salt = fields[1]

  return (module_generate_hash(word, salt), word)
