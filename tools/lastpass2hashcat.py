#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hansvh <6390369+hans-vh@users.noreply.github.com>
# Version: 0.0.6
# License: MIT

"""
Files can be found here:
Android: /data/data/com.lastpass.lpandroid/files
Others: See https://support.lastpass.com/help/where-is-my-lastpass-data-stored-on-my-computer-lp070008

Tested OK with:
- LastPass for Android (com.lastpass.lpandroid) v5.12.0.10004
- LastPass for Chrome v4.101.1
- LastPass for Opera v4.101.1
- LastPass for Firefox v4.101.0
"""

import sys
import os
import sqlite3
from base64 import b64decode
from re import search


def parse_encu(data):
    """Parse ENCU and return IV and AES-256-CBC encrypted email to compare against"""
    data = data.decode("utf-8")

    initialization_vector = None
    encrypted_email = None

    try:
        # Format: ![B64]|[B64]
        result = search(r"^!(.*)\|(.*)$", data)
        initialization_vector = result.group(1)
        encrypted_email = result.group(2)

        initialization_vector = b64decode(initialization_vector).hex()
        encrypted_email = b64decode(encrypted_email).hex()
    except:
        # B64 Only. This implies EBC, not CBC, mode and IV is found elsewhere, e.g., in database
        encrypted_email = b64decode(data).hex()

    return initialization_vector, encrypted_email


def open_file(file_name):
    """Open file and return contents"""
    with open(file_name, "rb") as file_handle:
        return file_handle.read()


def parse_vault(xml):
    """Parse Vault according to format: 4 bytes ASCII identifier, 4 bytes size, size bytes data"""
    magic_bytes = xml[:4].decode("utf-8")
    if magic_bytes != "LPAV":
        sys.exit(f"Expected LPAV in base 64 decoded XML, but found {magic_bytes}")

    offset = 0
    while offset < len(xml):
        identifier = xml[offset:offset + 4].decode("utf-8")
        offset = offset + 4
        size = int.from_bytes(xml[offset:offset + 4], byteorder='big')
        offset = offset + 4
        data = xml[offset:offset + size]

        if identifier == 'ENCU':
            initialization_vector, encrypted_email = parse_encu(data)
            return initialization_vector, encrypted_email

        offset = offset + size

    return None, None


def sqlite_parse_chromium(cur):
    """Chrome and Opera"""
    iterations = -1
    xml = ""
    try:
        res = cur.execute("SELECT data FROM LastPassData WHERE type='accts'")
        (xml,) = res.fetchone()
        result = search(r"^iterations=(\d+);(.*)$", xml)
        iterations = result.group(1)
        xml = result.group(2)
        xml = b64decode(xml)
    except:
        return None, None

    return iterations, xml


def sqlite_parse_firefox(cur):
    """Firefox"""
    iterations = -1
    encu = ""
    try:
        res = cur.execute("SELECT value FROM data WHERE key LIKE '%sch'")
        encu, = res.fetchone()
        encu = encu.decode("utf-8")
        encu = encu[encu.find("!"):]
        encu = encu[:encu.find("\n")]
        encu = bytes(encu, "utf-8")
        res = cur.execute("SELECT value FROM data WHERE key LIKE '%key_iter'")
        iterations, = res.fetchone()
        iterations = int(iterations)
    except:
        return None, None

    return iterations, encu


def main():
    """Entry point"""
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} <xml or sqlite file> <username (email)>")

    file_name = sys.argv[1]
    if not os.path.exists(file_name):
        sys.exit(f"File {file_name} does not exist")

    file_content = open_file(file_name)
    magic_bytes = file_content[:5].decode("utf-8")

    # Output will contain the following fields (in order), colon separated
    encrypted_email = ""
    iterations = -1
    email = sys.argv[2].lower()
    initialization_vector = ""

    if magic_bytes == "LPB64":
        # Android App
        iterations = 100100
        xml = b64decode(file_content[5:])
        initialization_vector, encrypted_email = parse_vault(xml)

    elif magic_bytes == "SQLit":
        # Browser Extension
        con = sqlite3.connect(file_name)
        cur = con.cursor()

        # First try Chromium based browsers
        iterations, xml = sqlite_parse_chromium(cur)
        if iterations and xml:
            initialization_vector, encrypted_email = parse_vault(xml)

        # Then try Firefox
        if not encrypted_email or not iterations or not initialization_vector:
            iterations, encu = sqlite_parse_firefox(cur)
            initialization_vector, encrypted_email = parse_encu(encu)

        # Finally give up
        if not encrypted_email or not iterations or not initialization_vector:
            sys.exit("Unexpected behaviour in SQLite database parsing")

        con.close()
    else:
        sys.exit(f"Expected LPB64 or SQLit in file, but found {magic_bytes}")

    print(f"{encrypted_email}:{iterations}:{email}:{initialization_vector}")


if __name__ == "__main__":
    main()
