#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

from lib.kerberos_rc4 import hmac_md5, ntlm_key, rc4
from lib.test_helpers import random_bytes, random_numeric_string

# Kerberos 5 AS-REQ Pre-Auth (krb5pa, etype 23). The RC4 key encrypts the PA-ENC-TIMESTAMP; on the
# verify path the stored ciphertext is decrypted and kept only when its timestamp is 14 digits.

MSG_TYPE = b"\x01\x00\x00\x00"


def get_random_kerberos5_salt(custom_salt, user, realm):
    # the kernels check the timestamp only for the "20" it starts with and the twelve digits after it

    clear_data = (
        random_bytes(14)
        + b"20"
        + random_numeric_string(12).encode("ascii")
        + random_bytes(8)
    )

    return f"{user}${realm}$salt${custom_salt.hex()}${clear_data.hex()}$"


def module_constraints():
    return [[0, 256], [16, 16], [0, 27], [16, 16], [-1, -1]]


def module_generate_hash(word, salt=None, iterations=None, user="user", realm="realm"):
    if salt is None or "$" not in salt:
        salt = get_random_kerberos5_salt(random_bytes(16), user, realm)

    arr = salt.split("$")

    user, realm, _salt_field = arr[0], arr[1], arr[2]

    hmac_salt = arr[3]
    hmac_salt_bin = bytes.fromhex(hmac_salt)

    clear_data = arr[4]

    k = ntlm_key(word)
    k1 = hmac_md5(k, MSG_TYPE)
    k3 = hmac_md5(k1, hmac_salt_bin)

    if len(clear_data) > 1:
        hash_buf = rc4(k3, bytes.fromhex(clear_data))
    else:
        hash_bin = bytes.fromhex(arr[5])

        decrypted = rc4(k3, hash_bin)

        timestamp = decrypted[14:28]

        is_numeric = len(timestamp) == 14 and all(0x30 <= b <= 0x39 for b in timestamp)

        if not is_numeric:
            hash_buf = b"\x00" * 36

            if hash_buf == hash_bin:
                hash_buf = b"\x01" * 36
        else:
            hash_buf = hash_bin

    return f"$krb5pa$23${user}${realm}${hmac_salt}${hash_buf.hex()}"


def module_verify_hash(line):
    s = line.decode("latin-1")

    colon = s.rfind(":")
    if colon < 1:
        return None

    hash_in = s[:colon]
    word = line[colon + 1 :]

    parts = hash_in.split("$")

    # canonical: $krb5pa$23$user$realm$checksum$encrypted -> 7 parts
    # legacy:    $krb5pa$23$user$realm$<104hex>           -> 6 parts

    if (
        len(parts) >= 7
        and parts[1] == "krb5pa"
        and parts[2] == "23"
        and len(parts[5]) == 32
    ):
        user = parts[3]
        realm = parts[4]
        hmac_salt = parts[5]
        enc_hex = parts[6]
        salt = f"{user}${realm}$salt${hmac_salt}$${enc_hex}"
        return (module_generate_hash(word, salt), word)

    if len(parts) >= 6 and parts[1] == "krb5pa" and parts[2] == "23":
        user = parts[3]
        realm = parts[4]
        data = parts[5]
        hmac_salt = data[-32:]
        enc_hex = data[:-32]
        salt = f"{user}${realm}$salt${hmac_salt}$${enc_hex}"
        return (module_generate_hash(word, salt), word)

    return None
