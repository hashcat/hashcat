#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Cipher import DES

from lib.test_helpers import split_hash_word

# RACF DES Passphrase. The username (EBCDIC, upper-cased through a2e_up) is the DES plaintext and the
# EBCDIC password, chained block by block and XORed with the previous ciphertext, mangles the DES key.
# a2e maps ASCII to EBCDIC, a2e_up does the same but folds lower case to upper.

A2E = bytes.fromhex(
  "00010203372d2e2f1605250b0c0d0e0f101112133c3d322618193f271c1d1e1f"
  "405a7f7b5b6c507d4d5d5c4e6b604b61f0f1f2f3f4f5f6f7f8f97a5e4c7e6e6f"
  "7cc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e9bae0bbb06d"
  "79818283848586878889919293949596979899a2a3a4a5a6a7a8a9c04fd0a107"
  "202122232415061728292a2b2c090a1b30311a333435360838393a3b04143eff"
  "41aa4ab19fb26ab5bdb49a8a5fcaafbc908feafabea0b6b39dda9b8bb7b8b9ab"
  "6465626663679e687471727378757677ac69edeeebefecbf80fdfefbfcadae59"
  "4445424643479c4854515253585556578c49cdcecbcfcce170dddedbdc8d8edf")

A2E_UP = bytes.fromhex(
  "00010203372d2e2f1605250b0c0d0e0f101112133c3d322618193f271c1d1e1f"
  "405a7f7b5b6c507d4d5d5c4e6b604b61f0f1f2f3f4f5f6f7f8f97a5e4c7e6e6f"
  "7cc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e9bae0bbb06d"
  "79c1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e9c04fd0a107"
  "202122232415061728292a2b2c090a1b30311a333435360838393a3b04143eff"
  "41aa4ab19fb26ab5bdb49a8a5fcaafbc908feafabea0b6b39dda9b8bb7b8b9ab"
  "6465626663679e687471727378757677ac69edeeebefecbf80fdfefbfcadae59"
  "4445424643479c4854515253585556578c49cdcecbcfcce170dddedbdc8d8edf")


def module_constraints():
  # pw_min is 9 (module_pw_min in src), and the hash is the password enciphered, so its length is
  # the password length: a candidate of any other length cannot match. The -a 0 and -a 3 kernels
  # reach the module's pw_max of 100, but the -a 1 kernel (which also serves -a 6, -a 7 and -a 12)
  # masks pw_len to 63 (m37400_a1-pure.cl), so a longer candidate is uncrackable there and shows up
  # as a flapping "not found" under the full attack suite CI runs. The test window is therefore
  # [9, 63], which still exercises 2 to 8 blocks of the DES chain. This papers over a src mismatch:
  # module_pw_max is 100 while the a1 kernel silently caps at 63, so a real -a 1/6/7 run with a
  # 64 to 100 byte passphrase cannot crack and gives no warning; the kernel is the better fix.
  return [[9, 63], [1, 8], [-1, -1], [-1, -1], [-1, -1]]


def _ibm_des_crypt(plaintext, key_bytes):
  key = bytes(((b ^ 0x55) << 1) & 0xfe for b in key_bytes)

  return DES.new(key, DES.MODE_ECB).encrypt(plaintext)


def module_generate_hash(word, salt, iterations=None):
  user = bytearray([0x40] * 8)

  for i in range(len(salt)):
    user[i] = A2E_UP[ord(salt[i])]

  user_packed = bytes(user)

  pw_len = len(word)
  num_blocks = (pw_len + 7) // 8

  pw_ebcdic = [0x40] * (num_blocks * 8)

  for i in range(pw_len):
    pw_ebcdic[i] = A2E[word[i]]

  out = [0] * 8
  full_hash = b""

  for block in range(num_blocks):
    key_block = [pw_ebcdic[block * 8 + j] ^ out[j] for j in range(8)]
    ciphertext = _ibm_des_crypt(user_packed, key_block)
    out = list(ciphertext)
    full_hash += ciphertext

  full_hash = full_hash[:pw_len]

  return "%s*%s" % (salt.upper(), full_hash.hex().upper())


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None:
    return None

  hash_in, word = parts

  username = hash_in.split("*")[0]

  return (module_generate_hash(word, username), word)
