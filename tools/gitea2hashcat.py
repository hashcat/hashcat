#!/usr/bin/python3
# Converts gitea PBKDF2-HMAC-SHA256 hashes into a format hashcat can use
# written by unix-ninja

import argparse
import base64
import sys

def convert_hash(hash_string):
    """Converts a SALT+HASH string to a hashcat compatible format,
       ensuring the smaller input is treated as the salt.
       Use : or | as delimeters.
    """
    hash_string = hash_string.replace('|', ':')
    try:
        part1, part2 = hash_string.split(":")
    except ValueError:
        print(f"[-] Invalid input format: {hash_string}")
        return None

    try:
        bytes1 = bytes.fromhex(part1)
        bytes2 = bytes.fromhex(part2)
    except ValueError:
      print(f"[-] Invalid hex input: {hash_string}")
      return None

    # If lengths are equal, we will maintain the original order
    if len(bytes1) > len(bytes2):
        salt_bytes = bytes2
        hash_bytes = bytes1
    else:  
        salt_bytes = bytes1
        hash_bytes = bytes2


    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')

    return f"sha256:50000:{salt_b64}:{hash_b64}"


def main():
    parser = argparse.ArgumentParser(description="Convert Gitea SALT+HASH strings to a hashcat-compatible format.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example:
    gitea2hashcat.py <salt1>:<hash1> <hash2>|<salt2> ... or pipe input from stdin.
        
    You can also dump output straight from sqlite into this script:
        sqlite3 gitea.db 'select salt,passwd from user;' | gitea2hashcat.py""")
    parser.add_argument('hashes', nargs='*', help='SALT+HASH strings to convert')
    args = parser.parse_args()

    # ... (rest of the main function remains the same)
    print("[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)")
    print()

    if args.hashes:
        # Process command-line arguments
        for hash_string in args.hashes:
            converted_hash = convert_hash(hash_string)
            if converted_hash:
                print(converted_hash)

    else:
        # Process input from stdin
        for line in sys.stdin:
            hash_string = line.strip()  # Remove leading/trailing whitespace
            converted_hash = convert_hash(hash_string)
            if converted_hash:
                print(converted_hash)


if __name__ == "__main__":
    main()
