#!/usr/bin/env python3

##
## Author......: Robert Guetzkow
## License.....: MIT
##

import struct

import hashlib

from Crypto.Cipher import AES

from lib.test_helpers import random_bytes

# KNX IP secure device authentication code. PBKDF2-HMAC-SHA256 turns the password into a 16 byte key
# that authenticates a Session_Response frame with AES-CCM. Only the MAC is reproduced here, as a
# CBC-MAC over the formatted associated data xored with the ECB encrypted nonce (the CCM S_0 block).


def device_authentication_code(password):
  return hashlib.pbkdf2_hmac("sha256", password,
                             b"device-authentication-code.1.secure.ip.knx.org", 65536, 16)


def block_formatting(b0, associated_data):
  associated_data_length = struct.pack(">h", len(associated_data))
  blocks_unpadded = associated_data_length + associated_data
  pad_len = ((len(blocks_unpadded) + 16 - 1) // 16) * 16
  blocks_padded = blocks_unpadded + b"\x00" * (pad_len - len(blocks_unpadded))

  return b0 + blocks_padded


def encrypt(blocks, nonce, key):
  iv = b"\x00" * 16

  ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(blocks)
  y_n = ciphertext[-16:]

  s_0 = AES.new(key, AES.MODE_ECB).encrypt(nonce)

  return bytes(a ^ b for a, b in zip(y_n, s_0))


def generate_session_response_mac(secure_session_identifier, public_value_xor, key):
  knx_ip_header = bytes.fromhex("061009520038")
  b0            = bytes.fromhex("00000000000000000000000000000000")
  nonce         = bytes.fromhex("0000000000000000000000000000ff00")

  associated_data = knx_ip_header + secure_session_identifier + public_value_xor

  blocks = block_formatting(b0, associated_data)

  return encrypt(blocks, nonce, key)


def module_constraints():
  return [[0, 20], [2, 2], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, public_value_xor=None):
  if isinstance(salt, str):
    salt = salt.encode("latin-1")

  if public_value_xor is None:
    public_value_xor = random_bytes(32)

  dac = device_authentication_code(word)

  mac = generate_session_response_mac(salt, public_value_xor, dac)

  return "$knx-ip-secure-device-authentication-code$*%s*%s*%s" % (salt.hex(), public_value_xor.hex(), mac.hex())


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in = line[:idx].decode(errors="replace")
  word    = line[idx + 1:]

  data = hash_in.split("*")

  if len(data) != 4:
    return None

  if data[0] != "$knx-ip-secure-device-authentication-code$":
    return None

  secure_session_identifier = bytes.fromhex(data[1])
  public_value_xor          = bytes.fromhex(data[2])
  mac                       = bytes.fromhex(data[3])

  if len(secure_session_identifier) != 2 or len(public_value_xor) != 32 or len(mac) != 16:
    return None

  return (module_generate_hash(word, secure_session_identifier, public_value_xor), word)
