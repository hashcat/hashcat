#!/usr/bin/env python3
"""
Extract a Firefox 146+ (SHA384 variant) master-password hash from a key4.db
in hashcat m26150 format.

Firefox 146 changed the KDF prelude from
    sha1  = SHA1(global_salt)            # 20-byte global salt
to
    sha384 = SHA384(global_salt || pwd)  # 48-byte global salt, full 48-byte digest

Detection: if metaData.item1 (global_salt) is 48 bytes the profile is the
SHA384 variant (m26150). 20 bytes means the legacy SHA1 variant (m26000) and
hashcat's existing tools/mozilla2hashcat.py should be used instead.

Output format (m26150, same shape as m26000):
    $mozilla$*AES*<global_salt>*<entry_salt>*<iter>*<iv>*<ct>

Usage:
    python3 mozilla2hashcat_sha384.py <profile_dir_or_key4.db>

Example profile paths (close Firefox first, the SQLite file is locked while
Firefox is running):
    Linux   : ~/.mozilla/firefox/<random>.default-release/
              e.g. ~/.mozilla/firefox/xxxxxxxx.default-release/
    macOS   : ~/Library/Application Support/Firefox/Profiles/<random>.default-release/
    Windows : %APPDATA%\\Mozilla\\Firefox\\Profiles\\<random>.default-release\\

You can also pass key4.db directly:
    python3 mozilla2hashcat_sha384.py ~/.mozilla/firefox/xxxxxxxx.default-release/key4.db

Find your active profile via ~/.mozilla/firefox/profiles.ini (look for the
[Install*] section's Default= entry, or the [Profile*] with Default=1).

Dependencies: Python stdlib only (sqlite3). A minimal DER parser is included
so no pyasn1/PyCryptodome install is required.
"""

import argparse
import binascii
import os
import sqlite3
import sys


def _der_read_len(buf, off):
    first = buf[off]
    off += 1
    if first & 0x80 == 0:
        return first, off
    n = first & 0x7F
    length = int.from_bytes(buf[off:off + n], "big")
    return length, off + n


def _der_parse(buf, off=0):
    """Parse one TLV. Returns (tag, value_bytes, next_off)."""
    tag = buf[off]
    length, off = _der_read_len(buf, off + 1)
    return tag, buf[off:off + length], off + length


def _der_children(seq_bytes):
    out = []
    off = 0
    while off < len(seq_bytes):
        tag, val, off = _der_parse(seq_bytes, off)
        out.append((tag, val))
    return out


def _oid_decode(val):
    if not val:
        return ""
    first = val[0]
    parts = [str(first // 40), str(first % 40)]
    i = 1
    while i < len(val):
        v = 0
        while True:
            b = val[i]
            i += 1
            v = (v << 7) | (b & 0x7F)
            if b & 0x80 == 0:
                break
        parts.append(str(v))
    return ".".join(parts)


def _int_decode(val):
    return int.from_bytes(val, "big", signed=False)


OID_PBES2 = "1.2.840.113549.1.5.13"
OID_PBKDF2 = "1.2.840.113549.1.5.12"
OID_HMAC_SHA256 = "1.2.840.113549.2.9"
OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"


def parse_item2(item2):
    """
    Parse the PBES2 ASN.1 blob from metaData.item2.

    Expected structure:
      SEQUENCE {
        SEQUENCE {                           -- AlgorithmIdentifier (PBES2)
          OID pbes2
          SEQUENCE {                         -- PBES2-params
            SEQUENCE {                       -- KDF
              OID pbkdf2
              SEQUENCE {
                OCTET STRING entry_salt
                INTEGER iterations
                INTEGER keyLength (32)
                SEQUENCE { OID hmac-sha256; NULL }
              }
            }
            SEQUENCE {                       -- encryption scheme
              OID aes-256-cbc
              OCTET STRING iv (14 bytes raw)
            }
          }
        }
        OCTET STRING ciphertext
      }
    """
    tag, outer, _ = _der_parse(item2)
    assert tag == 0x30, "top-level is not SEQUENCE"
    outer_children = _der_children(outer)
    assert len(outer_children) == 2

    alg_tag, alg_val = outer_children[0]
    ct_tag, ct_val = outer_children[1]
    assert alg_tag == 0x30 and ct_tag == 0x04

    alg_children = _der_children(alg_val)
    pbes2_oid_tag, pbes2_oid_val = alg_children[0]
    pbes2_params_tag, pbes2_params_val = alg_children[1]
    assert pbes2_oid_tag == 0x06
    assert _oid_decode(pbes2_oid_val) == OID_PBES2, "not a PBES2 blob"
    assert pbes2_params_tag == 0x30

    params_children = _der_children(pbes2_params_val)
    kdf_tag, kdf_val = params_children[0]
    enc_tag, enc_val = params_children[1]
    assert kdf_tag == 0x30 and enc_tag == 0x30

    # KDF: pbkdf2 OID + pbkdf2-params SEQUENCE
    kdf_children = _der_children(kdf_val)
    assert _oid_decode(kdf_children[0][1]) == OID_PBKDF2
    pbkdf2_params_children = _der_children(kdf_children[1][1])

    salt_tag, entry_salt = pbkdf2_params_children[0]
    iter_tag, iter_val = pbkdf2_params_children[1]
    keylen_tag, keylen_val = pbkdf2_params_children[2]
    prf_tag, prf_val = pbkdf2_params_children[3]
    assert salt_tag == 0x04
    assert iter_tag == 0x02
    assert keylen_tag == 0x02
    assert _int_decode(keylen_val) == 32
    prf_children = _der_children(prf_val)
    assert _oid_decode(prf_children[0][1]) == OID_HMAC_SHA256
    iterations = _int_decode(iter_val)

    # Encryption: aes256-cbc OID + OCTET STRING(iv_raw)
    enc_children = _der_children(enc_val)
    assert _oid_decode(enc_children[0][1]) == OID_AES256_CBC
    iv_raw_tag, iv_raw = enc_children[1]
    assert iv_raw_tag == 0x04

    # hashcat's mozilla2hashcat.py prepends the original DER OCTET STRING header
    # bytes b'\x04\x0e' to the IV. We reproduce that so the hash string is
    # byte-identical to what hashcat's format expects.
    iv = b"\x04\x0e" + iv_raw

    return entry_salt, iterations, iv, ct_val


def extract(db_path):
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = con.cursor()
    cur.execute("SELECT item1, item2 FROM metaData WHERE id = ?", ("password",))
    row = cur.fetchone()
    con.close()
    if row is None:
        raise SystemExit("metaData row id='password' not found — profile has no master password?")
    global_salt, item2 = row
    return global_salt, item2


def hexs(b):
    return binascii.hexlify(b).decode()


def main():
    ap = argparse.ArgumentParser(
        description="Extract Firefox 146+ (SHA384 variant) master password hash in hashcat m26150 format.",
        epilog=(
            "Example profile paths (close Firefox before running):\n"
            "  Linux  : ~/.mozilla/firefox/<random>.default-release/\n"
            "           e.g. ~/.mozilla/firefox/xxxxxxxx.default-release/\n"
            "  macOS  : ~/Library/Application Support/Firefox/Profiles/<random>.default-release/\n"
            "  Windows: %APPDATA%\\Mozilla\\Firefox\\Profiles\\<random>.default-release\\\n\n"
            "Look up the active profile in ~/.mozilla/firefox/profiles.ini."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "path",
        help="profile directory or key4.db file (e.g. ~/.mozilla/firefox/xxxxx.default-release/)",
    )
    args = ap.parse_args()

    p = args.path
    if os.path.isdir(p):
        p = os.path.join(p, "key4.db")
    if not os.path.isfile(p):
        sys.exit(f"key4.db not found at {p}")

    global_salt, item2 = extract(p)

    gs_len = len(global_salt)
    if gs_len == 20:
        sys.exit(
            "global_salt is 20 bytes — this is the legacy SHA1 variant (m26000).\n"
            "Use hashcat's tools/mozilla2hashcat.py for this profile."
        )
    if gs_len != 48:
        sys.exit(f"unexpected global_salt length {gs_len}; expected 48 (SHA384) or 20 (SHA1)")

    entry_salt, iterations, iv, ct = parse_item2(item2)

    print(
        f"$mozilla$*AES*{hexs(global_salt)}*{hexs(entry_salt)}*{iterations}*{hexs(iv)}*{hexs(ct)}"
    )


if __name__ == "__main__":
    main()
