#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from Crypto.Hash import MD4
from lib.kerberos_rc4 import hmac_md5, rc4
from lib.test_helpers import pack_hex, random_bytes, random_number, random_numeric_string

# Kerberos 5 AS-REQ Pre-Auth (NT hash variant, etype 23). Same as mode 07500 but the input is a
# 32-char hex NT hash instead of a password. The MD4 step is skipped.
# Format: $krb5pa$23$user$realm$salt$<enc_58-76hex><checksum_32hex>

MSG_TYPE = b"\x01\x00\x00\x00"

# the bytes after the 14 digits: the closing Z alone, or with a cusec of one, two or three bytes and
# its headers, which makes the encrypted timestamp 29, 34, 35 or 36 bytes long

TAIL_LENS = [1, 6, 7, 8]



def module_get_random_password(word):
  return MD4.new(word.decode("latin-1").encode("utf-16-le")).hexdigest().encode()


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [32, 32],
        'salt_length': [16, 16],
      },
      'optimized': None,
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm"):
    nt_hash = pack_hex(word)

    k1 = hmac_md5(nt_hash, MSG_TYPE)

    clear_data = (
        random_bytes(14)
        + b"20"
        + random_numeric_string(12).encode("ascii")
        + random_bytes(TAIL_LENS[random_number(0, len(TAIL_LENS) - 1)])
    )

    checksum = hmac_md5(k1, clear_data)
    k3 = hmac_md5(k1, checksum)

    hash_buf = rc4(k3, clear_data)

    return f"$krb5pa$23${user}${realm}$${hash_buf.hex()}{checksum.hex()}"


def module_verify_hash(line):
    s = line.decode("latin-1")

    if not s.startswith("$krb5pa$23$"):
        return None

    colon = s.rfind(":")
    if colon < 1:
        return None

    hash_in = s[:colon]
    word = line[colon + 1 :]

    parts = hash_in.split("$")
    if len(parts) < 6:
        return None

    user = parts[3]
    realm = parts[4]

    if len(parts) == 7:
        data = parts[6]
    elif len(parts) == 6:
        data = parts[5]
    else:
        return None

    if (len(data) < 90) or (len(data) > 108) or ((len(data) % 2) != 0):
        return None

    enc_hex = data[:-32]
    checksum_hex = data[-32:]

    checksum_bin = bytes.fromhex(checksum_hex)
    enc_bin = bytes.fromhex(enc_hex)

    nt_hash = pack_hex(word)

    k1 = hmac_md5(nt_hash, MSG_TYPE)
    k3 = hmac_md5(k1, checksum_bin)

    decrypted = rc4(k3, enc_bin)

    timestamp = decrypted[14:28]
    is_numeric = len(timestamp) == 14 and all(0x30 <= b <= 0x39 for b in timestamp)

    if not is_numeric:
        return None

    return (f"$krb5pa$23${user}${realm}$${enc_hex}{checksum_hex}", word)
