#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import pack_hex, random_bytes, random_number

# KeePass 1 and 2, keyfile only: the word is a 64 char hex string standing for the 32 raw keyfile
# bytes, which are hashed to a 32 byte key, transformed through many rounds of AES-256-ECB under a
# random seed and combined with the final seed. This differs from m13400 in two ways: the word is
# unpacked from hex before the first sha256, and version 2 does not sha256 the intermediate hash
# again. Version 1 with algorithm 1 uses Twofish, which has no stdlib or PyPI binding that runs on
# python 3.12, so it is implemented below and cross checked against the reference C library.


# --- Twofish (only version 1 with algorithm 1 uses it) ---

_Q0_T = [
  [0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4],
  [0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD],
  [0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1],
  [0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA],
]
_Q1_T = [
  [0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5],
  [0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8],
  [0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF],
  [0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA],
]


def _ror4(x, n):
  return ((x >> n) | (x << (4 - n))) & 0xf


def _build_q(t):
  out = []

  for x in range(256):
    a0, b0 = x >> 4, x & 0xf
    a1 = a0 ^ b0
    b1 = a0 ^ _ror4(b0, 1) ^ ((8 * a0) & 0xf)
    a2, b2 = t[0][a1], t[1][b1]
    a3 = a2 ^ b2
    b3 = a2 ^ _ror4(b2, 1) ^ ((8 * a2) & 0xf)
    a4, b4 = t[2][a3], t[3][b3]
    out.append((b4 << 4) | a4)

  return out


_Q0 = _build_q(_Q0_T)
_Q1 = _build_q(_Q1_T)

_MDS = [
  [0x01, 0xEF, 0x5B, 0x5B],
  [0x5B, 0xEF, 0xEF, 0x01],
  [0xEF, 0x5B, 0x01, 0xEF],
  [0xEF, 0x01, 0xEF, 0x5B],
]
_RS = [
  [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
  [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
  [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
  [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
]


def _gf(a, b, mod):
  p = 0

  for _ in range(8):
    if b & 1:
      p ^= a

    b >>= 1
    hi = a & 0x80
    a = (a << 1) & 0xff

    if hi:
      a ^= mod

  return p


def _rol32(x, n):
  return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _ror32(x, n):
  return ((x >> n) | (x << (32 - n))) & 0xffffffff


def _mds_mult(y):
  out = 0

  for r in range(4):
    v = 0

    for c in range(4):
      v ^= _gf(_MDS[r][c], y[c], 0x69)

    out |= v << (8 * r)

  return out


def _h(X, L):
  k = len(L)
  y = [(X >> (8 * i)) & 0xff for i in range(4)]
  Lb = [[(w >> (8 * i)) & 0xff for i in range(4)] for w in L]

  if k == 4:
    y[0] = _Q1[y[0]] ^ Lb[3][0]
    y[1] = _Q0[y[1]] ^ Lb[3][1]
    y[2] = _Q0[y[2]] ^ Lb[3][2]
    y[3] = _Q1[y[3]] ^ Lb[3][3]

  if k >= 3:
    y[0] = _Q1[y[0]] ^ Lb[2][0]
    y[1] = _Q1[y[1]] ^ Lb[2][1]
    y[2] = _Q0[y[2]] ^ Lb[2][2]
    y[3] = _Q0[y[3]] ^ Lb[2][3]

  y[0] = _Q1[_Q0[_Q0[y[0]] ^ Lb[1][0]] ^ Lb[0][0]]
  y[1] = _Q0[_Q0[_Q1[y[1]] ^ Lb[1][1]] ^ Lb[0][1]]
  y[2] = _Q1[_Q1[_Q0[y[2]] ^ Lb[1][2]] ^ Lb[0][2]]
  y[3] = _Q0[_Q1[_Q1[y[3]] ^ Lb[1][3]] ^ Lb[0][3]]

  return _mds_mult(y)


class _Twofish:
  def __init__(self, key):
    k = len(key) // 8
    words = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(2 * k)]
    Me = [words[2 * i] for i in range(k)]
    Mo = [words[2 * i + 1] for i in range(k)]

    S = []

    for i in range(k):
      m = key[8 * i:8 * i + 8]
      sw = 0

      for r in range(4):
        v = 0

        for c in range(8):
          v ^= _gf(_RS[r][c], m[c], 0x4D)

        sw |= v << (8 * r)

      S.append(sw)

    self.S = S[::-1]

    rho = 0x01010101
    K = []

    for i in range(20):
      A = _h((2 * i) * rho & 0xffffffff, Me)
      B = _rol32(_h((2 * i + 1) * rho & 0xffffffff, Mo), 8)
      K.append((A + B) & 0xffffffff)
      K.append(_rol32((A + 2 * B) & 0xffffffff, 9))

    self.K = K

  def _g(self, X):
    return _h(X, self.S)

  def encrypt(self, block):
    R = [int.from_bytes(block[4 * i:4 * i + 4], "little") ^ self.K[i] for i in range(4)]

    for r in range(16):
      T0 = self._g(R[0])
      T1 = self._g(_rol32(R[1], 8))
      F0 = (T0 + T1 + self.K[2 * r + 8]) & 0xffffffff
      F1 = (T0 + 2 * T1 + self.K[2 * r + 9]) & 0xffffffff
      R[2] = _ror32(R[2] ^ F0, 1)
      R[3] = _rol32(R[3], 1) ^ F1
      R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]

    R[0], R[1], R[2], R[3] = R[2], R[3], R[0], R[1]
    C = [R[i] ^ self.K[i + 4] for i in range(4)]

    return b"".join(c.to_bytes(4, "little") for c in C)

  def decrypt(self, block):
    C = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(4)]
    R = [C[2] ^ self.K[6], C[3] ^ self.K[7], C[0] ^ self.K[4], C[1] ^ self.K[5]]

    for r in range(15, -1, -1):
      in0, in1 = R[2], R[3]
      T0 = self._g(in0)
      T1 = self._g(_rol32(in1, 8))
      F0 = (T0 + T1 + self.K[2 * r + 8]) & 0xffffffff
      F1 = (T0 + 2 * T1 + self.K[2 * r + 9]) & 0xffffffff
      in2 = _rol32(R[0], 1) ^ F0
      in3 = _ror32(R[1] ^ F1, 1)
      R = [in0, in1, in2, in3]

    P = [R[i] ^ self.K[i] for i in range(4)]

    return b"".join(p.to_bytes(4, "little") for p in P)


# --- CBC helpers. Crypt::CBC standard padding is PKCS#7, and its unpad strips whatever the last
# byte counts, without validating, so this matches even the wrong password path. ---

def _pkcs7_pad(data):
  n = 16 - len(data) % 16

  return data + bytes([n]) * n


def _pkcs7_unpad(data):
  if not data:
    return data

  n = data[-1]

  return data[:-n] if 0 < n <= 16 else data


def _cbc_encrypt(enc_block, iv, data, pad):
  if pad:
    data = _pkcs7_pad(data)

  out = b""
  prev = iv

  for i in range(0, len(data), 16):
    blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
    prev = enc_block(blk)
    out += prev

  return out


def _cbc_decrypt(dec_block, iv, data, unpad):
  out = b""
  prev = iv

  for i in range(0, len(data), 16):
    ct = data[i:i + 16]
    out += bytes(a ^ b for a, b in zip(dec_block(ct), prev))
    prev = ct

  return _pkcs7_unpad(out) if unpad else out


# --- KeePass ---

def module_constraints():
  return [[64, 64], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def _split_star(s):
  # perl split ('\*', s) drops trailing empty fields

  arr = s.split("*")

  while arr and arr[-1] == "":
    arr.pop()

  return arr


def get_random_keepass_salt():
  version = random_number(1, 2)

  if version == 1:
    algorithm = random_number(0, 1)
    iteration = random_number(50000, 99999)
    final_random_seed = random_bytes(16).hex()
  else:
    algorithm = 0
    iteration = random_number(6000, 99999)
    final_random_seed = random_bytes(32).hex()

  transf_random_seed = random_bytes(32).hex()
  enc_iv = random_bytes(16).hex()
  contents_hash = random_bytes(32).hex()
  inline_flag = 1

  contents_len = random_number(128, 499)
  contents = random_bytes(contents_len)
  contents_len += 16 - contents_len % 16
  contents = contents.hex()

  # this mode cracks the keyfile itself, so the salt carries no keyfile attributes
  keyfile_attributes = ""

  if version == 1:
    return "*".join([str(version), str(iteration), str(algorithm), final_random_seed,
                     transf_random_seed, enc_iv, contents_hash, str(inline_flag),
                     str(contents_len), contents, keyfile_attributes])

  contents = random_bytes(32).hex()

  return "*".join([str(version), str(iteration), str(algorithm), final_random_seed,
                   transf_random_seed, enc_iv, contents_hash, contents, keyfile_attributes])


def module_generate_hash(word, salt, param=None):
  if len(salt) == 0:
    salt = get_random_keepass_salt()

  salt_arr = _split_star(salt)

  version = int(salt_arr[0])
  iteration = int(salt_arr[1])
  algorithm = int(salt_arr[2])

  final_random_seed = bytes.fromhex(salt_arr[3])
  transf_random_seed = bytes.fromhex(salt_arr[4])
  enc_iv = bytes.fromhex(salt_arr[5])

  keyfile_attributes = ""

  word_bin = pack_hex(word)

  intermediate_hash = hashlib.sha256(word_bin).digest()

  if version == 1:
    contents_hash = bytes.fromhex(salt_arr[6])
    inline_flag = int(salt_arr[7])
    contents_len = int(salt_arr[8])
    contents = bytes.fromhex(salt_arr[9])

    if len(salt_arr) == 13:
      inline_keyfile_flag = salt_arr[10]
      keyfile_len = salt_arr[11]
      keyfile_content = salt_arr[12]

      keyfile_attributes = "*" + inline_keyfile_flag + "*" + keyfile_len + "*" + keyfile_content

      intermediate_hash = hashlib.sha256(intermediate_hash + bytes.fromhex(keyfile_content)).digest()
  else:
    if len(salt_arr) == 11:
      inline_keyfile_flag = salt_arr[8]
      keyfile_len = salt_arr[9]
      keyfile_content = salt_arr[10]

      intermediate_hash = intermediate_hash + bytes.fromhex(keyfile_content)

      keyfile_attributes = "*" + inline_keyfile_flag + "*" + keyfile_len + "*" + keyfile_content

  ecb = AES.new(transf_random_seed, AES.MODE_ECB)

  for _ in range(iteration):
    intermediate_hash = ecb.encrypt(intermediate_hash)[0:32]

  intermediate_hash = hashlib.sha256(intermediate_hash).digest()

  final_key = hashlib.sha256(final_random_seed + intermediate_hash).digest()

  use_twofish = version == 1 and algorithm == 1

  if use_twofish:
    tf = _Twofish(final_key)
    enc_block, dec_block = tf.encrypt, tf.decrypt
  else:
    # separate objects because pycryptodome forbids mixing encrypt and decrypt on one ECB cipher
    enc_block = AES.new(final_key, AES.MODE_ECB).encrypt
    dec_block = AES.new(final_key, AES.MODE_ECB).decrypt

  if version == 1:
    if param is not None:
      contents = _cbc_decrypt(dec_block, enc_iv, contents, True)

      contents_hash_old = contents_hash
      contents_hash = hashlib.sha256(contents).digest()

      if contents_hash_old != contents_hash:
        contents = b"\x00" * len(contents)
    else:
      contents_hash = hashlib.sha256(contents).digest()

    contents = _cbc_encrypt(enc_block, enc_iv, contents, True)

    return "$keepass$*%d*%d*%d*%s*%s*%s*%s*%d*%d*%s%s" % (
      version, iteration, algorithm, final_random_seed.hex(), transf_random_seed.hex(),
      enc_iv.hex(), contents_hash.hex(), inline_flag, contents_len, contents.hex(),
      keyfile_attributes)

  contents_hash = bytes.fromhex(salt_arr[7])

  expected_bytes = _cbc_decrypt(dec_block, enc_iv, contents_hash, False)
  expected_bytes = (expected_bytes + b"\x00" * 32)[0:32]

  return "$keepass$*%d*%d*%d*%s*%s*%s*%s*%s%s" % (
    version, iteration, algorithm, final_random_seed.hex(), transf_random_seed.hex(),
    enc_iv.hex(), expected_bytes.hex(), contents_hash.hex(), keyfile_attributes)


def module_verify_hash(line):
  parts = line.split(b":")

  if len(parts) < 2:
    return None

  hash_in = parts[0].decode(errors="replace")
  word = parts[1]

  data = hash_in.split("*")

  if len(data) not in (9, 11, 12, 14):
    return None

  if data[0] != "$keepass$":
    return None

  version = data[1]

  if version not in ("1", "2"):
    return None

  final_random_seed = data[4]

  if version == "1":
    if len(final_random_seed) != 32:
      return None
  else:
    if len(final_random_seed) != 64:
      return None

  if len(data[5]) != 64:
    return None

  if len(data[6]) != 32:
    return None

  if version == "1":
    if len(data[7]) != 64:
      return None

    if data[8] != "1":
      return None

    contents_len = int(data[9]) if data[9].isdigit() else -1

    if len(data[10]) != contents_len * 2:
      return None
  else:
    if len(data[7]) != 64:
      return None

    if len(data[8]) != 64:
      return None

  salt = hash_in[len("$keepass$*"):]

  return (module_generate_hash(word, salt, 1), word)
