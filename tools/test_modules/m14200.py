#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib
import hmac
import struct

from Crypto.Cipher import AES, DES

from lib.test_helpers import random_hex_string

# RACF KDFAES. The username and password are folded into EBCDIC and DES to seed a proprietary,
# memory hard HMAC-SHA256 KDF, whose output keys an AES-256-ECB encryption of the username block.
#
# ascii2ebcdic uses Convert::EBCDIC's default table, which differs from cp500 in a few punctuation
# slots, so the exact 256 byte map is embedded here.

EBCDIC = bytes.fromhex(
  "00010203372d2e2f1605250b0c0d0e0f101112133c3d322618193f271c1d1e1f"
  "405a7f7b5b6c507d4d5d5c4e6b604b61f0f1f2f3f4f5f6f7f8f97a5e4c7e6e6f"
  "7cc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e9bae0bbb06d"
  "79818283848586878889919293949596979899a2a3a4a5a6a7a8a9c04fd0a107"
  "202122232415061728292a2b2c090a1b30311a333435360838393a3b04143eff"
  "41aa4ab19fb26ab5bdb49a8a5fcaafbc908feafabea0b6b39dda9b8bb7b8b9ab"
  "6465626663679e687471727378757677ac69edeeebefecbf80fdfefbfcadae59"
  "4445424643479c4854515253585556578c49cdcecbcfcce170dddedbdc8d8edf"
)


def module_constraints():
  return [[0, 8], [1, 8], [-1, -1], [-1, -1], [-1, -1]]


def ascii2ebcdic(data):
  return bytes(EBCDIC[b] for b in data)


def hmac_sha256(data, key):
  return hmac.new(key, data, hashlib.sha256).digest()


def xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


def prepare_hmac_key(username, password):
  username = (username.encode("latin-1") + b" " * 8)[:8]
  password = (password + b" " * 8)[:8]

  username_ebc = ascii2ebcdic(username)
  password_ebc = ascii2ebcdic(password)

  pw = bytes(((b ^ 0x55) << 1) & 0xff for b in password_ebc)

  cipher = DES.new(pw, DES.MODE_ECB)

  return cipher.encrypt(username_ebc)


def prepare_aes_key(mem_fac_exp, rep_fac, hmac_key, data_hex):
  mem_fac = (2 << (mem_fac_exp - 1)) // 32

  msg = bytes.fromhex(data_hex[:32]) + struct.pack(">I", mem_fac) + struct.pack(">I", 1)

  mem_buf = b""

  # step 1: proprietary PBKDF2-HMAC-SHA256, fill mem_buf

  for _ in range(mem_fac):
    u_current = hmac_sha256(msg, hmac_key)
    f_res = u_current
    h_prev = u_current

    for _ in range(rep_fac * 100 - 1):
      h_prev = u_current
      u_current = hmac_sha256(u_current, hmac_key)
      f_res = xor(f_res, u_current)

    msg = h_prev[:16] + f_res + struct.pack(">I", 1)
    mem_buf += f_res

  # step 2: mem_buf substitutions, keyed by the last 32 bytes

  hmac_key = mem_buf[-32:]

  for n in range(mem_fac):
    n_key = struct.unpack(">I", hmac_key[28:32])[0] & (mem_fac - 1)
    blk = hmac_sha256(mem_buf[n_key * 32:n_key * 32 + 32] + struct.pack(">I", 1), hmac_key)
    mem_buf = mem_buf[:n * 32] + blk + mem_buf[(n + 1) * 32:]
    hmac_key = blk

  # step 3: PBKDF2-HMAC-SHA256 over mem_buf, keyed by hmac_key (Crypt::PBKDF2 is salt, password)

  msg = mem_buf[:(mem_fac - 1) * 32]

  return hashlib.pbkdf2_hmac("sha256", hmac_key, msg, rep_fac * 100, 32)


def module_generate_hash(word, username, iterations=None, mem_fac=0x08, rep_fac=0x32, salt_data=None):
  if salt_data is None:
    salt_data = random_hex_string(32).upper()

  username = username.upper()

  hmac_key = prepare_hmac_key(username, word)

  aes_key = prepare_aes_key(mem_fac, rep_fac, hmac_key, salt_data)

  plaint = ascii2ebcdic(((username + " " * 8)[:8]).encode("latin-1")) + b"\x00" * 8

  ciphertext = AES.new(aes_key, AES.MODE_ECB).encrypt(plaint)

  return "$racf-kdfaes$*%s*E7D7E66D00018000%04X%04X00100010*%s*%s" % (
    username, mem_fac, rep_fac, salt_data.upper(), ciphertext.hex().upper())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  hash_elements = hash_in.split("*")

  if len(hash_elements) < 5 or hash_elements[0] != "$racf-kdfaes$":
    return None

  username = hash_elements[1]
  mem_fac = int(hash_elements[2][16:20], 16)
  rep_fac = int(hash_elements[2][20:24], 16)
  salt = hash_elements[3]

  new_hash = module_generate_hash(word, username, None, mem_fac, rep_fac, salt)

  return (new_hash, word)
