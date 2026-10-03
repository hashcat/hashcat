#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from lib.test_helpers import pack_hex, random_bytes, split_hash_word

# TACACS+: the key stream is MD5 of the session id, the password and the sequence, and the first six
# bytes of an authentication reply are what the kernel checks. A new hash encrypts a reply of its
# own; a line being verified has its reply decrypted and checked.
#
# The random session id goes through pack_hex () as raw bytes, which is what the perl did with it.


def module_constraints():
  return [[0, 243], [-1, -1], [0, 43], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None, encrypted_data=None, sequence=None):
  session_id = pack_hex(salt or random_bytes(8))
  sequence = pack_hex(sequence or "c006")

  key = hashlib.md5(session_id + word + sequence).digest()

  if encrypted_data is not None:
    enc = pack_hex(encrypted_data)

    plain = bytes(a ^ b for a, b in zip(enc[:6], key[:6]))

    ok = False

    if len(plain) == 6:
      status, flags = plain[0], plain[1]
      server_msg_len = int.from_bytes(plain[2:4], "big")
      data_len = int.from_bytes(plain[4:6], "big")

      ok = ((0x01 <= status <= 0x07) or status == 0x21) and flags in (0x00, 0x01) and \
           (6 + server_msg_len + data_len == len(enc))

    if not ok:
      enc = b""
  else:
    enc = bytes(a ^ b for a, b in zip(b"\x01\x00\x00\x00\x00\x00", key))

  return "$tacacs-plus$0$%s$%s$%s" % (session_id.hex(), enc.hex(), sequence.hex())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  data = hash_in.split("$")

  if len(data) != 6 or data[1] != "tacacs-plus" or data[2] != "0":
    return None

  return (module_generate_hash(word, data[3], None, data[4], data[5]), word)
