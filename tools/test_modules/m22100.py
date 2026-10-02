#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import kernel_charset, random_bytes, random_number, utf16le

# BitLocker. The optimized kernels widen each password byte instead of decoding the UTF-8, and
# module_01000.c documents that as deliberate, so the two kernel families disagree on a multi byte
# password. The oracle follows whichever test.sh is about to run: latin-1 reproduces the widening
# byte for byte, utf-8 is the conversion the pure kernels do. kernel_charset () reads IS_OPTIMIZED
# the same way test.sh sets it.

ITER     = 1048576  # 0x100000
SALT_LEN = 16
IV_LEN   = 12
MAC_LEN  = 16
VMK_LEN  = 44  # note: MAC_LEN + VMK_LEN = 60


def module_constraints():
  return [[6, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def bitlocker_kdf(initial_hash, salt):
  # password_key_data (88 bytes): 0-31 last_hash, 32-63 init_hash, 64-79 salt, 80-87 iter

  buf = bytearray(32 + 32 + 16 + 8)

  buf[32:64] = initial_hash
  buf[64:80] = salt

  for i in range(0x100000):
    buf[80:88] = i.to_bytes(8, "little")

    buf[0:32] = hashlib.sha256(buf).digest()

  return bytes(buf[0:32])  # AES-CCM key


def _xor(a, b):
  return bytes(x ^ y for x, y in zip(a, b))


# non-standard variant of AES-CCM (encrypt or decrypt are the same operation here)

def bitlocker_crypt_data(key, data, iv):
  aes = AES.new(key, AES.MODE_ECB)

  iiv = bytearray(b"\x02" + iv + b"\x00\x00\x00")

  ret = b""

  for blk, (start, length) in enumerate([(0, 16), (16, 16), (32, 16), (48, 12)]):
    iiv[15] = blk

    block = aes.encrypt(bytes(iiv))

    ret += _xor(data[start:start + length], block[:length])

  return ret


def bitlocker_generate_mac(key, data, iv):
  aes = AES.new(key, AES.MODE_ECB)

  iiv = b"\x3a" + iv + b"\x00\x00" + b"\x2c"

  block = aes.encrypt(iiv)
  res = _xor(data[0:16], block)

  block = aes.encrypt(res)
  res = _xor(data[16:32], block)

  block = aes.encrypt(res)
  res = _xor(data[32:44], block[:12])

  return aes.encrypt(res + block[12:16])


def module_generate_hash(word, salt, iv=None, data=None, type=None):
  salt_bytes = salt.encode("latin-1") if isinstance(salt, str) else salt

  if iv is None:
    iv = random_bytes(12)

  if type is None:
    type = random_number(0, 1)
  else:
    type = int(type)

  word_utf16le = utf16le(word, kernel_charset())

  pass_hash = hashlib.sha256(hashlib.sha256(word_utf16le).digest()).digest()

  key = bitlocker_kdf(pass_hash, salt_bytes)

  if not data:
    data = bytes.fromhex("2c000000") + bytes.fromhex("01000000") + bytes([random_number(0, 5)]) + \
           bytes.fromhex("200000") + random_bytes(44 - 12)
  else:
    dec_data = bitlocker_crypt_data(key, data, iv)

    data_size = dec_data[16] | (dec_data[17] << 8)
    version   = dec_data[20] | (dec_data[21] << 8)
    v1        = dec_data[16 + 8]
    v2        = dec_data[16 + 9]

    if data_size != 0x2c:
      return None
    if version != 0x01:
      return None
    if v2 != 0x20:
      return None
    if v1 > 0x05:
      return None

    data = dec_data[16:]  # skip the MAC, keep the raw VMK data

  mac = bitlocker_generate_mac(key, data, iv)

  enc_data = bitlocker_crypt_data(key, mac + data, iv)

  return "$bitlocker$%i$%i$%s$%i$%i$%s$%i$%s" % (
    type, SALT_LEN, salt_bytes.hex(), ITER, IV_LEN, iv.hex(), MAC_LEN + VMK_LEN, enc_data.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx].decode(errors="replace"), line[idx + 1:]

  data = hash_in.split("$")

  if len(data) != 10:
    return None

  signature = data[1]
  type      = data[2]
  salt_len  = data[3]
  salt      = data[4]
  iv_len    = data[6]
  iv        = data[7]
  data_len  = data[8]
  data_hex  = data[9]

  if signature != "bitlocker":
    return None

  if salt_len != str(SALT_LEN):
    return None
  if iv_len != str(IV_LEN):
    return None
  if data_len != str(MAC_LEN + VMK_LEN):
    return None

  try:
    salt = bytes.fromhex(salt)
    iv   = bytes.fromhex(iv)
    data = bytes.fromhex(data_hex)
  except ValueError:
    return None

  if len(salt) != SALT_LEN:
    return None
  if len(iv) != IV_LEN:
    return None
  if len(data) != MAC_LEN + VMK_LEN:
    return None

  new_hash = module_generate_hash(word, salt, iv, data, type)

  if new_hash is None:
    return None

  return (new_hash, word)
