#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import binascii
import random
import struct

from Crypto.Cipher import DES
from lib.kerberos_des import string_to_key
from lib.test_helpers import random_bytes, split_hash_word

# Kerberos 5 TGS-REP with des-cbc-crc (etype 1). Same string-to-key as etype 3, but the
# cipher uses IV=key, the header is 12 bytes (8 confounder + 4 CRC32), and the integrity
# check is CRC32 instead of MD5. ASN.1 markers sit at byte 12, not byte 24.

CLEARTEXT_TICKET = (
    "6381b03081ada00703050050a00000a11b3019a003020117a1"
    "12041058e0d77776e8b8e03991f2966939222aa2171b154d594b5242544553542e434f4e5"
    "44f534f2e434f4da3133011a003020102a10a30081b067472616e6365a40b3009a0030201"
    "01a1020400a511180f32303136303231353134343735305aa611180f32303136303231353"
    "134343735305aa711180f32303136303231363030343735305aa811180f32303136303232"
    "323134343735305a"
)


def _encrypt(key, data):
    return DES.new(key, DES.MODE_CBC, key).encrypt(data)


def _decrypt(key, data):
    return DES.new(key, DES.MODE_CBC, key).decrypt(data)


def _crc32(data):
    # Kerberos CRC-32: init=0, no final complement (RFC 3961 section 6)
    return ~binascii.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def _wrap(key, ticket):
    confounder = random_bytes(8)

    body = confounder + b"\x00" * 4 + ticket
    body += b"\x00" * ((-len(body)) % 8)

    crc = _crc32(body)

    body = confounder + struct.pack("<I", crc) + ticket
    body += b"\x00" * ((-len(body)) % 8)

    return _encrypt(key, body)


def _unwraps(key, cipher):
    plain = _decrypt(key, cipher)

    if plain[12] != 0x63:
        return False

    stored_crc = struct.unpack("<I", plain[8:12])[0]

    check_plain = plain[:8] + b"\x00" * 4 + plain[12:]

    return _crc32(check_plain) == stored_crc


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 64],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(
    word,
    salt=None,
    iterations=None,
    user="user",
    realm="realm",
    spn="test/spn",
    checksum=None,
    edata2=None,
    fmt=None,
):
    key = string_to_key(word, (realm.upper() + user).encode())

    if edata2 is None:
        cipher = _wrap(key, bytes.fromhex(CLEARTEXT_TICKET))
    else:
        cipher = bytes.fromhex(checksum + edata2)

        if not _unwraps(key, cipher):
            cipher = _wrap(key, bytes(len(CLEARTEXT_TICKET) // 2))

    if fmt is None:
        fmt = random.randint(1, 2)

    if fmt == 1:
        return (
            f"$krb5tgs$1$*{user}${realm}${spn}*${cipher[:16].hex()}${cipher[16:].hex()}"
        )
    else:
        return f"$krb5tgs$1${user}${realm}${cipher[:16].hex()}${cipher[16:].hex()}"


def module_verify_hash(line):
    parts = split_hash_word(line)

    if parts is None:
        return None

    hash_in, word = parts

    fields = hash_in.split("$")

    if len(fields) == 7 and fields[1] == "krb5tgs" and fields[2] == "1":
        fmt = 2
        user, realm, checksum, edata2 = fields[3], fields[4], fields[5], fields[6]
    elif len(fields) == 8 and fields[1] == "krb5tgs" and fields[2] == "1":
        fmt = 1
        user = fields[3][1:]
        realm = fields[4]
        spn = fields[5][:-1]
        checksum = fields[6]
        edata2 = fields[7]
    else:
        return None

    if len(checksum) != 32 or len(edata2) < 64 or len(edata2) % 16:
        return None

    if fmt == 1:
        return (
            module_generate_hash(
                word,
                user=user,
                realm=realm,
                spn=spn,
                checksum=checksum,
                edata2=edata2,
                fmt=fmt,
            ),
            word,
        )

    return (
        module_generate_hash(
            word, user=user, realm=realm, checksum=checksum, edata2=edata2, fmt=fmt
        ),
        word,
    )
