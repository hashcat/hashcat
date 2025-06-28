#!/usr/bin/env python3
#
# Script to extract the hash from a CacheData-file.
#--MicrosoftAccount
### C:\Windows\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\MicrosoftAccount\<unique_hash>\Cache\CacheData
#--AzureAD
### C:\Windows\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\AzureAD\<unique_hash>\Cache\CacheData
#
# This code is build from scratch. Nonetheless, all the initial reverse engineering work has been done
# by https://github.com/tijldeneut and https://github.com/synacktiv
#
# Authors:
#   https://github.com/Banaanhangwagen
#   https://github.com/Ctrl-Shift-Defeat
#
# v2025-5: initial release
#
# License: MIT
#

import sys
import struct

def read_node_info(file, node_count, start_address):
    """Extracts node info from the binary file."""
    node_info = []
    node_size = 20
    node_type_counts = {}
    for i in range(node_count):
        node_start = start_address + i * node_size
        node = file[node_start:node_start + node_size]
        node_type = node[0]
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
        crypto_blob_size = struct.unpack('<L', node[4:8])[0]
        encrypted_part_size = struct.unpack('<H', node[12:14])[0]
        node_info.append((node_type, crypto_blob_size, encrypted_part_size))
    return node_info, node_type_counts


def extract_hashes(file, node_info, start_address):
    # Process each node and extract the encoded blob
    hashes_found = 0
    for i, (node_type, crypto_blob_size, encrypted_part_size) in enumerate(node_info):
        if node_type == 1:
            # Skip 4 bytes header before crypto blob
            crypto_blob = file[start_address + 4:start_address + 4 + crypto_blob_size]
            start_address += 4 + crypto_blob_size

            # Skip 4 bytes header before encrypted part
            encrypted_part = file[start_address + 4:start_address + 4 + encrypted_part_size]
            start_address += 4 + encrypted_part_size

            # Output the hash in the required format
            hash_value = f"$MSONLINEACCOUNT$0$10000${encrypted_part.hex()[:64]}"
            print(f"\033[92m[+]\033[0m Hash: {hash_value:>111}")
            hashes_found += 1
        else:
            # Skip the other nodes properly
            start_address += crypto_blob_size + encrypted_part_size + 8

    return hashes_found


def print_banner():
    print("╔══════════════════════════════╗")
    print("║      Cachedata2hashcat       ║")
    print("╚══════════════════════════════╝")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} path_to_CacheData")
        sys.exit(1)
    try:
        with open(sys.argv[1], 'rb') as f:
            file = f.read()
    except IOError as e:
        print(f"Error opening file: {e}")
        sys.exit(1)

    print_banner()

    # Extract version
    version = struct.unpack('<L', file[0:4])[0]
    print(f"\033[92m[+]\033[0m CacheData file-version: {version:>5}")
    if version != 2:
        print("\033[91m[!]\033[0m Unsupported version. Be careful when proceeding.")

    # Extract node count
    node_count = struct.unpack('<L', file[0x50:0x54])[0]
    print(f"\033[92m[+]\033[0m Nodes counted: {node_count:>14}")
    if node_count == 0:
        print("\033[91m[!]\033[0m No nodes found. Cannot proceed.")
        sys.exit(1)

    node_info, node_type_counts = read_node_info(file, node_count, 0x54)

    type1_count = node_type_counts.get(1, 0)
    print(f"\033[92m[+]\033[0m Type 1-nodes: {type1_count:>15}")
    if type1_count == 0:
        print("\033[91m[!] Warning: No hash-containing nodes (Type 1) found.\033[0m")

    hashes_found = extract_hashes(file, node_info, 0x54 + node_count * 20)

    if hashes_found == 0:
        print(f"\033[91m[!]\033[0m No valid hashes found in the file.\033[0m")
    else:
        print(f"\033[92m[+]\033[0m Successfully extracted {hashes_found} hash(es).")


if __name__ == "__main__":
    main()
