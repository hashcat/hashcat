#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_rc4 import hmac_md5, rc4
from lib.test_helpers import pack_hex, random_bytes, random_numeric_string

# Kerberos 5 AS-REQ Pre-Auth (NT hash variant, etype 23). Same as mode 07500 but the input is a
# 32-char hex NT hash instead of a password. The MD4 step is skipped.
# Canonical format: $krb5pa$23$user$realm$<enc_timestamp_hex><checksum_hex>

MSG_TYPE = b"\x01\x00\x00\x00"


def module_constraints():
    return [[32, 32], [16, 16], [0, 27], [16, 16], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm"):
    nt_hash = pack_hex(word)

    k1 = hmac_md5(nt_hash, MSG_TYPE)

    clear_data = (
        random_bytes(14)
        + b"20"
        + random_numeric_string(12).encode("ascii")
        + random_bytes(8)
    )

    checksum = hmac_md5(k1, clear_data)
    k3 = hmac_md5(k1, checksum)

    hash_buf = rc4(k3, clear_data)

    return f"$krb5pa$23${user}${realm}${checksum.hex()}${hash_buf.hex()}"


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

    if len(parts) >= 7 and len(parts[5]) == 32:
        checksum_hex = parts[5]
        enc_hex = parts[6]
    else:
        data = parts[5]
        if len(data) < 104:
            return None
        checksum_hex = data[-32:]
        enc_hex = data[:-32]

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

    return (f"$krb5pa$23${user}${realm}${checksum_hex}${enc_hex}", word)
