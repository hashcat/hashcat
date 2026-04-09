#!/usr/bin/env python3

# Script to extract EC-SRP5 password hashes from Mikrotik RouterOS backup files
# for use with hashcat mode 33200
#
# Supports three input types:
#   1. .backup files (packed binary, plaintext only)
#   2. Unpacked backup directories (.dat/.idx pairs)
#   3. Monolithic config store files (cfg.* from NAND flash)
#
# Hash format: $mikrotik$<username>$<salt_hex_32>$<verifier_hex_56>
#
# References:
#   - BigNerd95/RouterOS-Backup-Tools (backup container format)
#   - Margin Research (nv::message / M2 record format)
#   - Kirils Solovjovs / 0ki/mikrotik-tools (original M2 parser)

import argparse
import os
import struct
import sys
from pathlib import Path


# -- Backup container constants --

MAGIC_PLAINTEXT = 0xB1A1AC88
MAGIC_RC4       = 0x7291A8EF
MAGIC_AES       = 0x7391A8EF

# -- M2 record type codes --

TYPE_BOOL_FALSE  = 0x00
TYPE_BOOL_TRUE   = 0x01
TYPE_U32         = 0x08
TYPE_U8          = 0x09
TYPE_U64         = 0x10
TYPE_128BIT      = 0x18
TYPE_STRING      = 0x21
TYPE_NESTED_M2   = 0x29
TYPE_RAW_BYTES   = 0x31
TYPE_ARRAY_U32   = 0x88
TYPE_ARRAY_STRING = 0xA0
TYPE_ARRAY_M2    = 0xA8

# -- M2 block IDs for user subsystem --

BLOCK_USERNAME        = 0x01   # type STRING
BLOCK_ECSRP5_SALT     = 0x20   # type RAW_BYTES, 16 bytes
BLOCK_ECSRP5_VERIFIER = 0x21   # type RAW_BYTES, 28+ bytes (first 28 used)

SALT_LEN     = 16
VERIFIER_LEN = 28


def parse_m2_fields(data, offset=0, length=None):
    """Parse M2 record fields. Returns list of (block_id, type_code, value)."""
    if length is None:
        length = len(data) - offset

    record = data[offset:offset + length]

    if len(record) < 2 or record[0:2] != b'M2':
        return None

    fields = []
    pos = 2

    while pos + 4 <= len(record):
        marker = struct.unpack_from('<I', record, pos)[0]
        pos += 4

        block_id = marker & 0xFFFFFF
        type_code = marker >> 24

        value = None

        if type_code in (TYPE_BOOL_FALSE, TYPE_BOOL_TRUE):
            value = (type_code == TYPE_BOOL_TRUE)

        elif type_code == TYPE_U32:
            if pos + 4 > len(record):
                break
            value = struct.unpack_from('<I', record, pos)[0]
            pos += 4

        elif type_code == TYPE_U8:
            if pos + 1 > len(record):
                break
            value = record[pos]
            pos += 1

        elif type_code == TYPE_U64:
            if pos + 8 > len(record):
                break
            value = struct.unpack_from('<Q', record, pos)[0]
            pos += 8

        elif type_code == TYPE_128BIT:
            if pos + 16 > len(record):
                break
            value = bytes(record[pos:pos + 16])
            pos += 16

        elif type_code == TYPE_STRING:
            if pos + 1 > len(record):
                break
            slen = record[pos]
            pos += 1
            if pos + slen > len(record):
                break
            value = record[pos:pos + slen]
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                value = None
            pos += slen

        elif type_code == TYPE_RAW_BYTES:
            if pos + 1 > len(record):
                break
            blen = record[pos]
            pos += 1
            if pos + blen > len(record):
                break
            value = bytes(record[pos:pos + blen])
            pos += blen

        elif type_code == TYPE_NESTED_M2:
            if pos + 1 > len(record):
                break
            sub_size = record[pos]
            pos += 1
            if pos + sub_size > len(record):
                break
            # Skip nested M2 records (not needed for hash extraction)
            pos += sub_size
            continue

        elif type_code == TYPE_ARRAY_U32:
            if pos + 2 > len(record):
                break
            count = struct.unpack_from('<H', record, pos)[0]
            pos += 2
            pos += count * 4
            continue

        elif type_code == TYPE_ARRAY_STRING:
            if pos + 2 > len(record):
                break
            count = struct.unpack_from('<H', record, pos)[0]
            pos += 2
            for _ in range(count):
                if pos + 2 > len(record):
                    break
                slen = struct.unpack_from('<H', record, pos)[0]
                pos += 2 + slen
            continue

        elif type_code == TYPE_ARRAY_M2:
            if pos + 2 > len(record):
                break
            count = struct.unpack_from('<H', record, pos)[0]
            pos += 2
            for _ in range(count):
                if pos + 2 > len(record):
                    break
                sub_size = struct.unpack_from('<H', record, pos)[0]
                pos += 2 + sub_size
            continue

        else:
            # Unknown type, cannot determine size
            break

        fields.append((block_id, type_code, value))

    return fields


def extract_hash_from_fields(fields):
    """Extract username, salt, verifier from parsed M2 fields.

    Returns (username, salt_hex, verifier_hex) or None.
    """
    username = None
    salt = None
    verifier = None

    for block_id, type_code, value in fields:
        if block_id == BLOCK_USERNAME and type_code == TYPE_STRING and value:
            username = value
        elif block_id == BLOCK_ECSRP5_SALT and type_code == TYPE_RAW_BYTES and value:
            salt = value
        elif block_id == BLOCK_ECSRP5_VERIFIER and type_code == TYPE_RAW_BYTES and value:
            verifier = value

    if username and salt and verifier:
        if len(salt) < SALT_LEN:
            return None
        if len(verifier) < VERIFIER_LEN:
            return None
        salt_hex = salt[:SALT_LEN].hex()
        verifier_hex = verifier[:VERIFIER_LEN].hex()
        return (username, salt_hex, verifier_hex)

    return None


def format_hash(username, salt_hex, verifier_hex):
    """Format as hashcat hash line."""
    return f"$mikrotik${username}${salt_hex}${verifier_hex}"


# -- .dat/.idx parser --

def parse_dat_records(dat_data, idx_data=None):
    """Parse M2 records from a .dat file (optionally with .idx).

    Yields list of (block_id, type_code, value) field lists.
    """
    if idx_data:
        cumulative_pos = 0
        pos = 0
        while pos + 12 <= len(idx_data):
            record_id = struct.unpack_from('<I', idx_data, pos)[0]
            length = struct.unpack_from('<I', idx_data, pos + 4)[0]
            pos += 12
            cumulative_pos += length

            if record_id == 0xFFFFFFFF:
                continue

            dat_offset = cumulative_pos - length
            if dat_offset + 2 > len(dat_data):
                continue
            rec_size = struct.unpack_from('<H', dat_data, dat_offset)[0]
            if dat_offset + rec_size > len(dat_data):
                continue

            fields = parse_m2_fields(dat_data, dat_offset + 2, rec_size - 2)
            if fields is not None:
                yield fields
    else:
        # No index: try sequential parse first, then fall back to M2 scanning
        records_found = 0
        dat_pos = 0
        while dat_pos + 4 <= len(dat_data):
            rec_size = struct.unpack_from('<H', dat_data, dat_pos)[0]
            if rec_size < 4 or dat_pos + rec_size > len(dat_data):
                break
            if dat_data[dat_pos + 2:dat_pos + 4] != b'M2':
                break
            fields = parse_m2_fields(dat_data, dat_pos + 2, rec_size - 2)
            if fields is not None:
                yield fields
                records_found += 1
            dat_pos += rec_size

        if records_found <= 1:
            # Sequential parse got stuck; scan for M2 markers instead
            seen_offsets = set()
            pos = 0
            while pos + 2 <= len(dat_data):
                idx = dat_data.find(b'M2', pos)
                if idx < 0:
                    break
                if idx in seen_offsets:
                    pos = idx + 2
                    continue
                seen_offsets.add(idx)
                # Try to determine record boundary: check for size prefix
                rec_end = len(dat_data)
                if idx >= 2:
                    candidate_size = struct.unpack_from('<H', dat_data, idx - 2)[0]
                    if 4 <= candidate_size <= len(dat_data) - idx + 2:
                        rec_end = idx + candidate_size - 2
                # Try parsing from this M2 marker to next M2 or end
                next_m2 = dat_data.find(b'M2', idx + 2)
                if next_m2 > 0 and next_m2 >= 2:
                    # Use the smaller bound
                    alt_end = next_m2 - 2  # approximate: size prefix of next record
                    if alt_end > idx:
                        rec_end = min(rec_end, alt_end)
                length = rec_end - idx
                if length < 2:
                    pos = idx + 2
                    continue
                fields = parse_m2_fields(dat_data, idx, length)
                if fields is not None:
                    yield fields
                pos = idx + 2


def extract_from_dat_idx(dat_data, idx_data=None):
    """Extract hashes from user.dat/user.idx data.

    Yields (username, salt_hex, verifier_hex) tuples.
    """
    for fields in parse_dat_records(dat_data, idx_data):
        result = extract_hash_from_fields(fields)
        if result:
            yield result


def scan_raw_ecsrp5(data):
    """Scan raw binary data for EC-SRP5 verifier/salt/username patterns.

    This is a fallback for when structured parsing fails. It looks for the
    raw M2 block encoding: block_id(3 bytes LE) + type(1 byte) + length(1 byte) + data.

    Yields (username, salt_hex, verifier_hex) tuples.
    """
    VERIFIER_MARKER = bytes([0x21, 0x00, 0x00, 0x31])  # block_id=0x21, type=RAW_BYTES
    SALT_MARKER     = bytes([0x20, 0x00, 0x00, 0x31])  # block_id=0x20, type=RAW_BYTES
    USER_MARKER     = bytes([0x01, 0x00, 0x00, 0x21])  # block_id=0x01, type=STRING

    seen = set()

    for i in range(len(data) - 60):
        if data[i:i+4] != VERIFIER_MARKER:
            continue

        vlen = data[i+4]
        if vlen < 28 or vlen > 40:
            continue
        verifier = data[i+5:i+5+28]

        # Look for salt block within 40 bytes after verifier
        rest = data[i+5+vlen:]
        if len(rest) < 25:
            continue
        salt_idx = rest[:40].find(SALT_MARKER)
        if salt_idx < 0:
            continue
        slen = rest[salt_idx+4]
        if slen != 16:
            continue
        salt = rest[salt_idx+5:salt_idx+5+16]

        # Look for username block within 40 bytes after salt
        rest2 = rest[salt_idx+5+16:]
        user_idx = rest2[:40].find(USER_MARKER)
        if user_idx < 0:
            continue
        ulen = rest2[user_idx+4]
        if ulen < 1 or ulen > 64:
            continue
        try:
            username = rest2[user_idx+5:user_idx+5+ulen].decode('utf-8')
        except UnicodeDecodeError:
            continue

        key = (username, salt.hex())
        if key not in seen:
            seen.add(key)
            yield (username, salt.hex(), verifier.hex())


# -- cfg.* monolithic parser --

def parse_cfg_index(data):
    """Parse section index from cfg.* file.

    Returns (sections_dict, data_start_offset).
    """
    sections = {}
    pos = 4  # skip 4 initial zero bytes
    last_null = 0

    while pos + 8 < len(data):
        sec_id = data[pos]
        sec_ver = data[pos + 1]
        name_len = struct.unpack_from('<I', data, pos + 4)[0]

        if name_len == 0 or name_len > 200:
            break
        if sec_ver not in range(1, 20):
            break
        if pos + 8 + name_len >= len(data):
            break

        name_raw = data[pos + 8:pos + 8 + name_len]
        try:
            name = name_raw.decode('ascii')
        except UnicodeDecodeError:
            break

        if not all(c.isalnum() or c in '/-_.' for c in name):
            break

        sections[sec_id] = (sec_ver, name)
        null_pos = pos + 8 + name_len
        last_null = null_pos
        pos = null_pos + 4

    return sections, last_null


def extract_from_cfg(data):
    """Extract hashes from a monolithic cfg.* file.

    Yields (username, salt_hex, verifier_hex) tuples.
    """
    sections, data_start = parse_cfg_index(data)

    # Find which section IDs correspond to 'user'
    user_sec_ids = set()
    for sec_id, (ver, name) in sections.items():
        if name == 'user':
            user_sec_ids.add(sec_id)

    if not user_sec_ids:
        return

    pos = data_start
    while pos + 12 <= len(data):
        sec_id = data[pos]
        # sec_ver = data[pos + 1]
        rec_size = struct.unpack_from('<I', data, pos + 8)[0]

        if rec_size < 2 or rec_size > 100000:
            break
        if pos + 12 + rec_size > len(data):
            break

        if sec_id in user_sec_ids:
            fields = parse_m2_fields(data, pos + 12, rec_size)
            if fields is not None:
                result = extract_hash_from_fields(fields)
                if result:
                    yield result

        pos += 12 + rec_size


# -- .backup container parser --

def unpack_backup(data):
    """Unpack a RouterOS .backup file.

    Returns dict of {filename: file_data} for all embedded files.
    Raises ValueError for encrypted or invalid backups.
    """
    if len(data) < 8:
        raise ValueError("File too small to be a RouterOS backup")

    magic = struct.unpack_from('<I', data, 0)[0]

    if magic == MAGIC_RC4:
        raise ValueError("Backup is RC4 encrypted. Decrypt it first "
                         "(e.g., with RouterOS-Backup-Tools)")
    if magic == MAGIC_AES:
        raise ValueError("Backup is AES encrypted. Decrypt it first "
                         "(e.g., with RouterOS-Backup-Tools)")
    if magic != MAGIC_PLAINTEXT:
        raise ValueError(f"Unrecognized file magic: 0x{magic:08X}. "
                         f"Expected 0x{MAGIC_PLAINTEXT:08X} (plaintext backup)")

    file_size = struct.unpack_from('<I', data, 4)[0]
    pos = 8

    files = {}
    while pos + 4 <= len(data):
        # Read filename
        name_len = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if pos + name_len > len(data):
            break
        filename = data[pos:pos + name_len].decode('ascii', errors='replace')
        pos += name_len

        # Read idx data
        if pos + 4 > len(data):
            break
        idx_len = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if pos + idx_len > len(data):
            break
        idx_data = data[pos:pos + idx_len]
        pos += idx_len

        # Read dat data
        if pos + 4 > len(data):
            break
        dat_len = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if pos + dat_len > len(data):
            break
        dat_data = data[pos:pos + dat_len]
        pos += dat_len

        files[filename] = (idx_data, dat_data)

    return files


def extract_from_backup(data):
    """Extract hashes from a packed .backup file.

    Yields (username, salt_hex, verifier_hex) tuples.
    """
    files = unpack_backup(data)

    for filename, (idx_data, dat_data) in files.items():
        # Only look at user data files
        basename = filename.rstrip('/').split('/')[-1]
        if basename != 'user':
            continue
        idx = idx_data if len(idx_data) > 0 else None
        yield from extract_from_dat_idx(dat_data, idx)


# -- Unpacked backup directory --

def extract_from_directory(dir_path):
    """Extract hashes from an unpacked backup directory.

    Looks for user.dat (with optional user.idx) in the directory tree.
    Yields (username, salt_hex, verifier_hex) tuples.
    """
    dir_path = Path(dir_path)
    found = False

    for dat_file in dir_path.rglob('user.dat'):
        found = True
        idx_file = dat_file.with_suffix('.idx')
        dat_data = dat_file.read_bytes()
        idx_data = idx_file.read_bytes() if idx_file.exists() else None
        yield from extract_from_dat_idx(dat_data, idx_data)

    if not found:
        print(f"Warning: no user.dat found in {dir_path}", file=sys.stderr)


# -- Auto-detect input type --

def detect_and_extract(path):
    """Auto-detect input type and extract hashes.

    Yields (username, salt_hex, verifier_hex) tuples.
    """
    path = Path(path)

    if path.is_dir():
        yield from extract_from_directory(path)
        return

    data = path.read_bytes()

    if len(data) < 4:
        print(f"Error: file too small: {path}", file=sys.stderr)
        return

    magic = struct.unpack_from('<I', data, 0)[0]

    # Check for .backup container (magic at offset 0)
    if magic in (MAGIC_PLAINTEXT, MAGIC_RC4, MAGIC_AES):
        yield from extract_from_backup(data)
        return

    # Check for .backup container with 2-byte prefix (magic at offset 2)
    if len(data) > 6:
        magic2 = struct.unpack_from('<I', data, 2)[0]
        if magic2 in (MAGIC_PLAINTEXT, MAGIC_RC4, MAGIC_AES):
            yield from extract_from_backup(data[2:])
            return

    # Check for cfg.* monolithic config store
    # Format: starts with 4 zero bytes followed by section index
    # Some files have a 2-byte prefix before the standard format
    cfg_data = None
    if data[0:4] == b'\x00\x00\x00\x00' and len(data) > 12:
        if data[5] in range(1, 20):
            cfg_data = data
    elif len(data) > 14 and data[2:6] == b'\x00\x00\x00\x00':
        if data[7] in range(1, 20):
            cfg_data = data[2:]

    if cfg_data is not None:
        results = list(extract_from_cfg(cfg_data))
        if results:
            yield from results
            return
        # cfg index parsed but no user hashes found — fall through to M2 scan

    # Check for raw .dat file (starts with record size + M2 magic)
    if len(data) > 4:
        rec_size = struct.unpack_from('<H', data, 0)[0]
        if 4 < rec_size < len(data) and data[2:4] == b'M2':
            yield from extract_from_dat_idx(data)
            return

    # Last resort: raw binary scan for EC-SRP5 patterns
    if len(data) > 60:
        results = list(scan_raw_ecsrp5(data))
        if results:
            print(f"Warning: using raw binary scan for: {path}", file=sys.stderr)
            yield from results
            return

    print(f"Error: unrecognized file format or no EC-SRP5 hashes: {path}",
          file=sys.stderr)
    print("Supported formats: .backup (plaintext), unpacked backup directory, "
          "cfg.* config store, user.dat", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Extract Mikrotik RouterOS EC-SRP5 hashes for hashcat (mode 33200)',
        epilog='Supported inputs:\n'
               '  .backup file     Plaintext RouterOS backup (encrypted not supported)\n'
               '  directory        Unpacked backup directory with .dat/.idx files\n'
               '  cfg.* file       Monolithic config store from NAND flash\n'
               '  user.dat file    Raw user data file from unpacked backup\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input', nargs='+',
                        help='RouterOS backup file, unpacked backup directory, '
                             'cfg.* config store, or user.dat file')

    args = parser.parse_args()

    found = 0
    seen = set()

    for input_path in args.input:
        if not os.path.exists(input_path):
            print(f"Error: {input_path}: no such file or directory",
                  file=sys.stderr)
            continue

        try:
            for username, salt_hex, verifier_hex in detect_and_extract(input_path):
                hash_line = format_hash(username, salt_hex, verifier_hex)
                if hash_line not in seen:
                    seen.add(hash_line)
                    print(hash_line)
                    found += 1
        except ValueError as e:
            print(f"Error: {input_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Error: {input_path}: {e}", file=sys.stderr)

    if found == 0:
        print("No EC-SRP5 hashes found. Users may have old-style MD5 passwords "
              "(RouterOS < 6.45) or no password set.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
