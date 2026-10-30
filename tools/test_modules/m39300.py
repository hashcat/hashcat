#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import struct

from Crypto.Cipher import DES
from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 AS-REQ Pre-Auth with des-cbc-crc (etype 1). Same as mode 39000 (etype 3 PA)
# but with IV=key, 12-byte header (8 confounder + 4 CRC32), and CRC32 integrity instead
# of MD5.

# PA-ENC-TS-ENC: SEQUENCE { [0] GeneralizedTime "20190101000000Z", [1] INTEGER 123456 }
CLEARTEXT_TIMESTAMP = "301aa011180f32303139303130313030303030305aa105020301e240"


def _encrypt(key, data):
    return DES.new(key, DES.MODE_CBC, key).encrypt(data)


def _decrypt(key, data):
    return DES.new(key, DES.MODE_CBC, key).decrypt(data)


def _crc32(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return crc


def _wrap(key, msg):
    confounder = random_bytes(8)

    body = confounder + b"\x00" * 4 + msg
    body += b"\x00" * ((-len(body)) % 8)

    crc = _crc32(body)

    body = confounder + struct.pack("<I", crc) + msg
    body += b"\x00" * ((-len(body)) % 8)

    return _encrypt(key, body)


def _unwraps(key, cipher):
    plain = _decrypt(key, cipher)

    # the timestamp starts at byte 12 (after 8 confounder + 4 CRC32) and must open with
    # a SEQUENCE tag (0x30)

    if plain[12] != 0x30:
        return False

    stored_crc = struct.unpack("<I", plain[8:12])[0]

    check_plain = plain[:8] + b"\x00" * 4 + plain[12:]

    return _crc32(check_plain) == stored_crc


def module_constraints():
    return [[0, 64], [16, 16], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(
    word, salt=None, iterations=None, user="user", realm="realm", data=None
):
    key = string_to_key(word, (realm.upper() + user).encode())

    if data is None:
        cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TIMESTAMP))
    else:
        cipher = bytes.fromhex(data)

        if not _unwraps(key, cipher):
            cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TIMESTAMP))

    return f"$krb5pa$1${user}${realm}${cipher.hex()}"


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    fields = hash_in.split("$")

    if len(fields) != 6 or fields[1] != "krb5pa" or fields[2] != "1":
        return None

    user, realm, data = fields[3], fields[4], fields[5]

    if len(data) < 64 or len(data) % 16:
        return None

    return (module_generate_hash(word, user=user, realm=realm, data=data), word)
