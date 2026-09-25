#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_number, random_hex_string

# ENCsecurity Data Vault, MD5 key derivation with a keychain. The MD5 derived key decrypts a 128
# byte keychain in the parallel AES-ECB counter mode, and the keychain supplies the key that
# decrypts the data. The known-plaintext marker is checked over 56 bits only, see
# https://github.com/hashcat/hashcat/issues/3467.

ENC_MAX_KEY_NUM            = 8
ENC_NONCE_SIZE             = 8
ENC_KEY_SIZE               = 16
ENC_BLOCK_SIZE             = 16
ENC_KEYCHAIN_SIZE          = 128
ENC_DEFAULT_MD5_ITERATIONS = 1000

DEFAULT_SALTS = [
  bytes.fromhex("0fc9e7d08be424f6569d4e72edbc2c5c"),
  bytes.fromhex("dd7974f33d8300c29bd293d57f9d9b8c"),
  bytes.fromhex("60850c475846e2962d995d5ef1d06a28"),
  bytes.fromhex("e23f3d6b99614ba9c4edc5ddd8253ce1"),
  bytes.fromhex("2ca459891d7852db3031d09f9f348835"),
  bytes.fromhex("db1bb527e8214f79a0b2cb3242d9f20a"),
  bytes.fromhex("aea8b68ed07b62a1400e17c6ad6420c8"),
  bytes.fromhex("eae3f44eaf4a8f84f1fab3088569bef8"),
]


def _xor_len(in1, in2, length):
  return bytes(in1[i] ^ in2[i] for i in range(length))


def _md5_key(word):
  key = b"\x00" * 16

  tmp = hashlib.md5(word).digest()

  for _ in range(1, ENC_DEFAULT_MD5_ITERATIONS):
    tmp = hashlib.md5(tmp).digest()

    key = _xor_len(key, tmp, 16)

  out = b""

  for i in range(ENC_MAX_KEY_NUM):
    out += _xor_len(key, DEFAULT_SALTS[i], 16)

  return out


def _ctr_stream(aes, ivs, num_keys, counter_start, nblocks):
  out_all = b""

  counter = counter_start

  for _ in range(nblocks):
    counter_be = counter.to_bytes(8, "big")

    out = aes.encrypt(ivs[0] + counter_be)

    for i in range(1, num_keys):
      enc = aes.encrypt(ivs[i] + counter_be)

      out = _xor_len(enc, out, ENC_BLOCK_SIZE)

    out_all += out

    counter += 1

  return out_all


def module_constraints():
  return [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt=None, algo=None, iv=None, ct=None, keychain=None):
  if algo is None:
    algo = random_number(1, 4)

  if iv is None:
    iv = random_hex_string(16)

  if keychain is None:
    keychain = random_hex_string(256)

  algo = int(algo)

  nb_keys = 1 << (algo - 1)

  key = _md5_key(word)

  aes = AES.new(key[0:ENC_KEY_SIZE], AES.MODE_ECB)

  keychain_bin = bytes.fromhex(keychain)

  ivs_keychain = [(0).to_bytes(8, "big")]

  for i in range(1, ENC_MAX_KEY_NUM):
    # note: the key material skips 8 bytes every 16, matching the reference implementation
    next8 = key[(ENC_MAX_KEY_NUM - i) * ENC_KEY_SIZE:(ENC_MAX_KEY_NUM - i) * ENC_KEY_SIZE + ENC_NONCE_SIZE]

    ivs_keychain.append(next8)

  ctr_keychain = _ctr_stream(aes, ivs_keychain, ENC_MAX_KEY_NUM, 0, ENC_KEYCHAIN_SIZE // ENC_BLOCK_SIZE)

  result = _xor_len(keychain_bin, ctr_keychain, ENC_KEYCHAIN_SIZE)

  # the keychain now supplies the key that decrypts the data
  aes = AES.new(result[0:ENC_KEY_SIZE], AES.MODE_ECB)

  iv_bin = bytes.fromhex(iv)

  ivs = [iv_bin]

  for i in range(1, nb_keys):
    next8 = result[i * ENC_KEY_SIZE:i * ENC_KEY_SIZE + ENC_NONCE_SIZE]

    ivs.append(_xor_len(iv_bin, next8, 8))

  ctr_len = 16

  ctr = _ctr_stream(aes, ivs, nb_keys, 1, ctr_len // ENC_BLOCK_SIZE)

  if ct is not None:
    ct_bin = bytes.fromhex(ct)

    pt_bin = _xor_len(ctr[4:4 + 8], ct_bin, 8)

    # compare only 56 bits, see hashcat issue 3467
    if pt_bin[0:7] == b"\xd2\xc3\xb4\xa1\x00\x00\x00":
      pass
    else:
      pt_bin = b"\xff\xff\xff\xff\xff\xff\xff\xff"
  else:
    pt_bin = b"\xd2\xc3\xb4\xa1\x00\x00\x00\x30"

  ct_bin = _xor_len(ctr[4:4 + 8], pt_bin, 8)

  return "$encdv$3$%d$%s$%s$%s" % (algo, iv_bin.hex(), ct_bin.hex(), keychain_bin.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word = line[idx + 1:]

  if hash_in[0:7] != "$encdv$":
    return None

  fields = hash_in.split("$")

  # ['', signature, version, algo, iv, ct, keychain]
  if len(fields) != 7:
    return None

  version = fields[2]
  algo = fields[3]
  iv = fields[4]
  ct = fields[5]
  keychain = fields[6]

  if version != "3":
    return None

  if not algo.isdigit() or int(algo) < 1 or int(algo) > 4:
    return None

  new_hash = module_generate_hash(word, None, algo, iv, ct, keychain)

  return (new_hash, word)
