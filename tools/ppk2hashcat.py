#!/usr/bin/env python3
"""
ppk2hashcat - Extract hash from PuTTY Private Key (PPK) files for hashcat

Supports PPK version 2 and 3 files with AES-256-CBC encryption.

Usage:
    python3 ppk2hashcat.py <ppk_file> [ppk_file2 ...]

Output format (v2):
    $ppk$2*algorithm*encryption*comment_hex*public_len*public_hex*private_len*private_hex*mac_hex

Output format (v3):
    $ppk$3*algorithm*encryption*comment*argon2_memory*argon2_passes*argon2_parallelism*argon2_salt*pub_len*pub*priv_len*priv*mac
"""

import sys
import base64
import binascii
import re


def parse_ppk_file(filename):
    """Parse a PuTTY Private Key (PPK) file and extract components."""
    
    with open(filename, 'r') as f:
        content = f.read()
    
    lines = content.strip().split('\n')
    
    # Parse header
    header_match = re.match(r'^PuTTY-User-Key-File-(\d+):\s*(.+)$', lines[0])
    if not header_match:
        raise ValueError(f"Invalid PPK file header: {lines[0]}")
    
    version = int(header_match.group(1))
    algorithm = header_match.group(2).strip()
    
    if version not in (2, 3):
        raise ValueError(f"Unsupported PPK version {version} (only 2 and 3 are supported)")
    
    # Parse the rest of the file
    encryption = None
    comment = None
    public_lines = []
    private_lines = []
    mac = None
    
    # PPK v3 specific fields
    key_derivation = None
    argon2_memory = None
    argon2_passes = None
    argon2_parallelism = None
    argon2_salt = None
    
    i = 1
    while i < len(lines):
        line = lines[i]
        
        if line.startswith('Encryption:'):
            encryption = line.split(':', 1)[1].strip()
        elif line.startswith('Comment:'):
            comment = line.split(':', 1)[1].strip()
        elif line.startswith('Public-Lines:'):
            num_lines = int(line.split(':', 1)[1].strip())
            public_lines = lines[i+1:i+1+num_lines]
            i += num_lines
        elif line.startswith('Private-Lines:'):
            num_lines = int(line.split(':', 1)[1].strip())
            private_lines = lines[i+1:i+1+num_lines]
            i += num_lines
        elif line.startswith('Private-MAC:'):
            mac = line.split(':', 1)[1].strip()
        # PPK v3 specific fields
        elif line.startswith('Key-Derivation:'):
            key_derivation = line.split(':', 1)[1].strip()
        elif line.startswith('Argon2-Memory:'):
            argon2_memory = int(line.split(':', 1)[1].strip())
        elif line.startswith('Argon2-Passes:'):
            argon2_passes = int(line.split(':', 1)[1].strip())
        elif line.startswith('Argon2-Parallelism:'):
            argon2_parallelism = int(line.split(':', 1)[1].strip())
        elif line.startswith('Argon2-Salt:'):
            argon2_salt = line.split(':', 1)[1].strip()
        
        i += 1
    
    if encryption is None:
        raise ValueError("Missing Encryption field")
    if encryption == 'none':
        raise ValueError("PPK file is not encrypted (Encryption: none)")
    if encryption != 'aes256-cbc':
        raise ValueError(f"Unsupported encryption: {encryption} (only aes256-cbc is supported)")
    if comment is None:
        comment = ""
    if not public_lines:
        raise ValueError("Missing Public-Lines")
    if not private_lines:
        raise ValueError("Missing Private-Lines")
    if mac is None:
        raise ValueError("Missing Private-MAC")
    
    # PPK v3 validation
    if version == 3:
        if key_derivation is None:
            raise ValueError("Missing Key-Derivation field for PPK v3")
        if key_derivation != 'Argon2id':
            raise ValueError(f"Unsupported key derivation: {key_derivation} (only Argon2id is supported)")
        if argon2_memory is None:
            raise ValueError("Missing Argon2-Memory field for PPK v3")
        if argon2_passes is None:
            raise ValueError("Missing Argon2-Passes field for PPK v3")
        if argon2_parallelism is None:
            raise ValueError("Missing Argon2-Parallelism field for PPK v3")
        if argon2_salt is None:
            raise ValueError("Missing Argon2-Salt field for PPK v3")
    
    # Decode base64 data
    public_blob = base64.b64decode(''.join(public_lines))
    private_blob = base64.b64decode(''.join(private_lines))
    
    # Ensure private blob is multiple of 16 bytes (AES block size)
    if len(private_blob) % 16 != 0:
        raise ValueError(f"Private blob length ({len(private_blob)}) is not a multiple of 16")
    
    result = {
        'version': version,
        'algorithm': algorithm,
        'encryption': encryption,
        'comment': comment,
        'public_blob': public_blob,
        'private_blob': private_blob,
        'mac': mac
    }
    
    if version == 3:
        result['key_derivation'] = key_derivation
        result['argon2_memory'] = argon2_memory
        result['argon2_passes'] = argon2_passes
        result['argon2_parallelism'] = argon2_parallelism
        result['argon2_salt'] = argon2_salt
    
    return result


def ppk_to_hashcat(ppk_data):
    """Convert parsed PPK data to hashcat hash format."""
    
    algorithm_hex = binascii.hexlify(ppk_data['algorithm'].encode('utf-8')).decode('ascii')
    encryption_hex = binascii.hexlify(ppk_data['encryption'].encode('utf-8')).decode('ascii')
    comment_hex = binascii.hexlify(ppk_data['comment'].encode('utf-8')).decode('ascii')
    public_hex = binascii.hexlify(ppk_data['public_blob']).decode('ascii')
    private_hex = binascii.hexlify(ppk_data['private_blob']).decode('ascii')
    mac_hex = ppk_data['mac']
    
    version = ppk_data['version']
    
    if version == 2:
        # Format: $ppk$2*algorithm*encryption*comment*pub_len*pub*priv_len*priv*mac
        hash_string = f"$ppk${version}*{algorithm_hex}*{encryption_hex}*{comment_hex}*" \
                      f"{len(ppk_data['public_blob'])}*{public_hex}*" \
                      f"{len(ppk_data['private_blob'])}*{private_hex}*{mac_hex}"
    elif version == 3:
        # Format: $ppk$3*algorithm*encryption*comment*argon2_memory*argon2_passes*argon2_parallelism*argon2_salt*pub_len*pub*priv_len*priv*mac
        hash_string = f"$ppk${version}*{algorithm_hex}*{encryption_hex}*{comment_hex}*" \
                      f"{ppk_data['argon2_memory']}*{ppk_data['argon2_passes']}*{ppk_data['argon2_parallelism']}*" \
                      f"{ppk_data['argon2_salt']}*" \
                      f"{len(ppk_data['public_blob'])}*{public_hex}*" \
                      f"{len(ppk_data['private_blob'])}*{private_hex}*{mac_hex}"
    else:
        raise ValueError(f"Unsupported PPK version: {version}")
    
    return hash_string


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ppk_file> [ppk_file2 ...]", file=sys.stderr)
        print("\nExtracts hash from PuTTY PPK files for use with hashcat.", file=sys.stderr)
        print("Supports PPK version 2 and 3 files with AES-256-CBC encryption.", file=sys.stderr)
        print("\nHashcat modes:", file=sys.stderr)
        print("  PPK v2 (SHA1):    99200", file=sys.stderr)
        print("  PPK v3 (Argon2):  99210", file=sys.stderr)
        sys.exit(1)
    
    for filename in sys.argv[1:]:
        try:
            ppk_data = parse_ppk_file(filename)
            hash_string = ppk_to_hashcat(ppk_data)
            print(hash_string)
        except FileNotFoundError:
            print(f"Error: File not found: {filename}", file=sys.stderr)
        except ValueError as e:
            print(f"Error parsing {filename}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error processing {filename}: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
