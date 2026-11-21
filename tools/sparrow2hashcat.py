#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Extracts the crackable payload from a password-protected Sparrow Wallet
# file (.mv.db, SPRW1 container: H2 2.x MVStore with XTS-AES-128 file
# encryption, key derived via Argon2id by drongo's Argon2KeyDeriver).
#
# File layout (confirmed against Sparrow DbPersistence.writeBinaryHeader and
# H2 2.1.214 FileEncrypt):
#   offset  0: "H2encrypt\n"        (10 bytes, H2 FileEncrypt.HEADER)
#   offset 10: h2 salt              (8 bytes, H2 FileEncrypt salt)
#   offset 18: "SPRW1\n"            (6 bytes, Sparrow magic)
#   offset 24: Argon2id salt        (16 bytes)
#   offset 40..4095: zero padding   (rest of the 4096-byte header block)
#   offset 4096+: XTS-AES-128 encrypted MVStore data, unit 0 holds the
#                 store header "H:2,block:...,..."
#
# Usage: sparrow2hashcat.py wallet.mv.db [more.mv.db ...]
###

import sys
import os

H2_HEADER = b"H2encrypt\n"
SPRW1_MAGIC = b"SPRW1\n"
HEADER_BLOCK = 4096
CT_LEN = 64


def extract(path):
    try:
        with open(path, "rb") as f:
            header = f.read(HEADER_BLOCK)
            ct = f.read(CT_LEN)
    except OSError as e:
        return None, f"cannot read file: {e}"

    if len(header) < 40:
        return None, "file too small for a SPRW1 header"

    if header[:10] != H2_HEADER:
        if header[:2] == b"H:":
            return None, "file is an unencrypted H2 MVStore (no password set?)"
        return None, "missing 'H2encrypt' magic (not an encrypted H2 file)"

    if header[18:24] != SPRW1_MAGIC:
        return None, "missing 'SPRW1' magic (not a Sparrow wallet file)"

    if len(ct) < CT_LEN:
        return None, "file too small for the first encrypted block (truncated?)"

    argon_salt = header[24:40]
    h2salt = header[10:18]

    if argon_salt == b"\x00" * 16:
        return None, "Argon2 salt is all zeros (corrupted header?)"

    return ("$sparrow$1$%s$%s$%s"
            % (argon_salt.hex(), h2salt.hex(), ct.hex())), None


def main():
    if len(sys.argv) < 2:
        print("usage: %s wallet.mv.db [more.mv.db ...]" % os.path.basename(sys.argv[0]),
              file=sys.stderr)
        sys.exit(1)

    exit_code = 0

    for path in sys.argv[1:]:
        line, err = extract(path)
        if err:
            print("%s: %s" % (path, err), file=sys.stderr)
            exit_code = 1
        else:
            print(line)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
