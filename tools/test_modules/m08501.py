#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

# AS/400 DES: the EBCDIC user name is DES encrypted under a key derived from the EBCDIC
# password, each password byte xored with 0x55 and shifted left one bit. Convert::EBCDIC's
# table is Python's cp037. Name and password are space padded to 8 bytes.
#
# Passwords of 9-10 characters add a SECOND DES block: the same user name encrypted under a
# key built from characters 9-10 (space padded). The stored hash is then both blocks, 32 hex.
# User names of 9-10 characters are folded down to 8 bytes before encryption.


def _ebcdic(s):
  return s.decode("latin-1").encode("cp037")


def _fold_username(username):
  buf = bytearray(b"\x40" * 10)

  ebc = _ebcdic(username)

  for i in range(min(len(ebc), 10)):
    buf[i] = ebc[i]

  if len(username) > 8:
    buf[0] ^=  buf[8] & 0xC0
    buf[1] ^= ((buf[8] & 0x30) << 2) & 0xff
    buf[2] ^= ((buf[8] & 0x0C) << 4) & 0xff
    buf[3] ^= ((buf[8] & 0x03) << 6) & 0xff
    buf[4] ^=  buf[9] & 0xC0
    buf[5] ^= ((buf[9] & 0x30) << 2) & 0xff
    buf[6] ^= ((buf[9] & 0x0C) << 4) & 0xff
    buf[7] ^= ((buf[9] & 0x03) << 6) & 0xff

  return bytes(buf[:8])


def _des_block(username_ebc, password_chars):
  password = (password_chars + b" " * 8)[:8]

  password_ebc = _ebcdic(password)

  key = bytes(((b ^ 0x55) << 1) & 0xff for b in password_ebc)

  return DES.new(key, DES.MODE_ECB).encrypt(username_ebc)


def as400_des(username, password):
  username_ebc = _fold_username(username)

  out = _des_block(username_ebc, password[:8])

  if len(password) > 8:
    out += _des_block(username_ebc, password[8:])

  return out.hex()


def module_constraints():
  return [[0, 10], [1, 10], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  # the mode is OPTS_TYPE_PT_UPPER / OPTS_TYPE_ST_UPPER, so hashcat upper-cases both the
  # candidate and the salt before hashing. Match that here or mixed-case words never verify.
  hash_buf = as400_des(salt.upper().encode("latin-1"), word.upper())

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
