#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import random
import string

from lib.kerberos_rc4 import hmac_md5, ntlm_key, rc4
from lib.test_helpers import random_bytes, random_numeric_string

# Kerberos 5 AS-REQ Pre-Auth (krb5pa, etype 23). The RC4 key encrypts the PA-ENC-TIMESTAMP; on the
# verify path the stored ciphertext is decrypted and kept only when its timestamp is 14 digits.

MSG_TYPE = b"\x01\x00\x00\x00"


def get_random_kerberos5_salt(custom_salt):
    # the kernels check the timestamp only for the "20" it starts with and the twelve digits after it

    fmt = random.randint(1, 3)

    user_len = random.randint(1, 253)
    realm_len = random.randint(1, 253)
    salt_len = random.randint(0, 128)

    user = "".join(random.choices(string.ascii_lowercase, k=user_len))
    realm = "".join(random.choices(string.ascii_uppercase, k=realm_len))
    salt_field = "".join(random.choices(string.ascii_letters, k=salt_len))

    clear_data = (
        random_bytes(14)
        + b"20"
        + random_numeric_string(12).encode("ascii")
        + random_bytes(8)
    )

    return "%s$%s$%s$%s$%s$%d" % (
        user,
        realm,
        salt_field,
        custom_salt.hex(),
        clear_data.hex(),
        fmt,
    )


def module_test_properties():
  return {
    'constraints': {
      'pure': {
        'password_length': [0, 256],
        'salt_length': [16, 16],
      },
      'optimized': {
        'password_length': [0, 27],
        'salt_length': [16, 16],
      },
      'combined_length': None,
    },
  }


def module_generate_hash(word, salt, iterations=None):
    if "$" not in salt:
        salt = get_random_kerberos5_salt(salt.encode("latin-1"))

    arr = salt.split("$")

    user, realm, salt_field = arr[0], arr[1], arr[2]

    hmac_salt = arr[3]
    hmac_salt_bin = bytes.fromhex(hmac_salt)

    clear_data = arr[4]

    k = ntlm_key(word)
    k1 = hmac_md5(k, MSG_TYPE)
    k3 = hmac_md5(k1, hmac_salt_bin)

    if len(clear_data) > 1:
        hash_buf = rc4(k3, bytes.fromhex(clear_data))
        fmt = int(arr[5]) if len(arr) > 5 and arr[5].isdigit() else 1
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

        fmt = int(arr[6]) if len(arr) > 6 and arr[6].isdigit() else 1

    if fmt == 1:
        return "$krb5pa$23$%s$%s$%s$%s%s" % (
            user,
            realm,
            salt_field,
            hash_buf.hex(),
            hmac_salt,
        )
    elif fmt == 3:
        return "$krb5pa$23$%s$%s$%s$%s" % (user, realm, hmac_salt, hash_buf.hex())
    else:
        return "$krb5pa$23$%s$%s$%s%s" % (user, realm, hash_buf.hex(), hmac_salt)


def module_verify_hash(line):
    s = line.decode("latin-1")

    if not s.startswith("$krb5pa$23$"):
        return None

    # find user and realm fields
    index1 = s.find("$", 11)
    if index1 < 0:
        return None

    index2 = s.find("$", index1 + 1)
    if index2 < 0:
        return None

    user = s[11:index1]
    realm = s[index1 + 1 : index2]

    # find : separator between hash and password (hex data never contains :)
    colon = s.find(":", index2 + 1)
    if colon < 0:
        return None

    word = line[colon + 1 :]

    # everything between realm$ and :password determines the format
    hash_tail = s[index2 + 1 : colon]

    dollar = hash_tail.find("$")

    if dollar < 0:
        # format 2: user$realm$<enc><cksum>
        fmt = 2
        salt_field = ""
        hmac_salt = hash_tail[-32:]
        enc_hex = hash_tail[:-32]
    else:
        field_before = hash_tail[:dollar]
        field_after = hash_tail[dollar + 1 :]

        if (
            len(field_before) == 32
            and all(c in "0123456789abcdefABCDEF" for c in field_before)
            and len(field_after) >= 58
            and len(field_after) <= 76
        ):
            # format 3: user$realm$<cksum32>$<enc>
            fmt = 3
            salt_field = ""
            hmac_salt = field_before
            enc_hex = field_after
        else:
            # format 1: user$realm$salt$<enc><cksum>
            fmt = 1
            salt_field = field_before
            hmac_salt = field_after[-32:]
            enc_hex = field_after[:-32]

    salt_str = "%s$%s$%s$%s$$%s$%d" % (
        user,
        realm,
        salt_field,
        hmac_salt,
        enc_hex,
        fmt,
    )

    return (module_generate_hash(word, salt_str), word)
