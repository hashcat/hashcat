#!/usr/bin/env python3

"""
kremlin2hashcat.py for Kremlin Encrypt 3.0 (using NewDES)
Author......: hansvh
License.....: MIT

Note:
Kremlin stores non-ascii characters as one byte hex (e.g. iso-8859-15), not variable length.

Crack the password blåbærsyltetøy as follows:
1. hashcat '$kgb$2ed936a4394bbc30$11c44ae3d4d39114cc47a6efb5d6bb89cf2be943' -a3 bl?bb?brsyltet?by # ?b includes non printable characters
2. hashcat '$kgb$2ed936a4394bbc30$11c44ae3d4d39114cc47a6efb5d6bb89cf2be943' -a0 utf-8-wordlist.txt --encoding-to=iso-8859-15

The result in both cases is
$kgb$2ed936a4394bbc30$11c44ae3d4d39114cc47a6efb5d6bb89cf2be943:$HEX[626ce562e67273796c746574f879]
"""

from sys import argv, stderr
from os import path


def read_file_contents(filename):
    """Return salt and expected/correct SHA1 hash from file"""

    with open(filename, "rb") as file_handle:
        magic = file_handle.read(128)
        if magic != bytes.fromhex("0e0401010101011027010157494e2000000001004b524d" + 210 * "0"):
            stderr.write(f"Unexpected magic bytes in {filename}. Skipping!\n")
            return None, None
        salt = file_handle.read(8)
        correct_sha1 = file_handle.read(20)

    return (salt.hex(), correct_sha1.hex())


def usage():
    """Print correct program usage and exit"""
    exit(f'Usage: {argv[0]} <encrypted1.kgb> ... <encryptedN.kgb>')


def main():
    """Entry point"""
    if len(argv) < 2:
        usage()

    for filename in argv[1:]:
        if path.isfile(filename):
            salt, correct_hash = read_file_contents(filename)
            if salt and correct_hash:
                print(f"$kgb${salt}${correct_hash}")


if __name__ == "__main__":
    main()
