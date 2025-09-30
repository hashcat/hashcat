#!/usr/bin/env bash

# BIP39 Passphrase Recovery - Example Usage (Mode 32001)
#
# This example demonstrates cracking a known BIP39 passphrase using hashcat.
#
# Hash format: mnemonic:target_address:derivation_path
# Example uses the "abandon..." test mnemonic with passphrase "testpass"

# Create example wordlist
cat > example32001.txt <<EOF
password
testpass
mypassphrase
EOF

# Run hashcat (CUDA backend only - requires --backend-ignore-opencl)
./hashcat -m 32001 example32001.hash example32001.txt \
  --backend-devices 1 \
  --backend-ignore-opencl \
  --force

# Expected output:
# abandon abandon...about:33747aCmUp8PkWmWWY8epR1Cph8Tf9Aozt:m/49'/0'/0'/0/0:testpass
# Status...........: Cracked

# Cleanup
rm -f example32001.txt
