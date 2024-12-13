#!/usr/bin/env python3

# Author......: See docs/credits.txt
# License.....: MIT
# Target......: Exodus wallet extractor
# Example.....: exodus2hashcat.py <path to exodus seed seco file>

from __future__ import annotations

import hashlib
import struct
from argparse import ArgumentParser
from base64 import b64encode
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from struct import Struct


# consts


SIGNATURE = "EXODUS"

HEADER_MAGIC = b"SECO"
HEADER_VERSION = 0
HEADER_VERSION_TAG = b"seco-v0-scrypt-aes"
HEADER_SIZE = 224

CHECKSUM_SIZE = 256 // 8

METADATA_SALT_SIZE = 32
METADATA_CIPHER_SIZE = 32
METADATA_BLOB_KEY_IV_SIZE = 12
METADATA_BLOB_KEY_AUTH_TAG_SIZE = 16
METADATA_BLOB_KEY_KEY_SIZE = 32
METADATA_BLOB_IV_SIZE = 12
METADATA_BLOB_AUTH_TAG_SIZE = 16
METADATA_SIZE = 256


# structs


@dataclass
class File:
    header: Header
    checksum: bytes
    metadata: Metadata
    blob: bytes


@dataclass
class Header:
    magic: bytes
    version: int
    version_tag: bytes
    app_name: bytes
    app_version: bytes


@dataclass(init=False)
class Metadata:
    class Cipher(str, Enum):
        AES_256_GCM = "aes-256-gcm"

    @dataclass
    class BlobKey:
        iv: bytes
        auth_tag: bytes
        key: bytes

    @dataclass
    class Blob:
        iv: bytes
        auth_tag: bytes

    salt: bytes
    n: int
    r: int
    p: int
    cipher: Cipher
    blob_key: BlobKey
    blob: Blob

    def __init__(self, salt, n, r, p, cipher, blob_key, blob):
        self.salt = salt
        self.n = n
        self.r = r
        self.p = p
        if isinstance(cipher, bytes):
            cipher = cipher.rstrip(b"\x00")
            cipher = cipher.decode()
        cipher = self.Cipher(cipher)
        self.cipher = cipher
        self.blob_key = blob_key
        self.blob = blob


# header


def read_header(file):
    # prepare structs
    partial_header_struct = Struct(">4sL4x")
    byte_struct = Struct(">B")

    # read whole header space
    file = BytesIO(file.read(HEADER_SIZE))

    # read partial header
    partial_header = file.read(partial_header_struct.size)
    if len(partial_header) < partial_header_struct.size:
        raise ValueError("file contains less data than needed")
    partial_header = partial_header_struct.unpack(partial_header)

    # read header version tag
    header_version_tag_length = file.read(byte_struct.size)
    if len(header_version_tag_length) < byte_struct.size:
        raise ValueError("file contains less data than needed")
    (header_version_tag_length,) = byte_struct.unpack(header_version_tag_length)
    header_version_tag = file.read(header_version_tag_length)
    if len(header_version_tag) < header_version_tag_length:
        raise ValueError("file contains less data than needed")

    # read header app name
    header_app_name_length = file.read(byte_struct.size)
    if len(header_app_name_length) < byte_struct.size:
        raise ValueError("file contains less data than needed")
    (header_app_name_length,) = byte_struct.unpack(header_app_name_length)
    header_app_name = file.read(header_app_name_length)
    if len(header_app_name) < header_app_name_length:
        raise ValueError("file contains less data than needed")

    # read header app version
    header_app_version_length = file.read(byte_struct.size)
    if len(header_app_version_length) < byte_struct.size:
        raise ValueError("file contains less data than needed")
    (header_app_version_length,) = byte_struct.unpack(header_app_version_length)
    header_app_version = file.read(header_app_version_length)
    if len(header_app_version) < header_app_version_length:
        raise ValueError("file contains less data than needed")

    # make header
    header = Header(*partial_header, header_version_tag, header_app_name, header_app_version)

    return header


# checksum


def read_checksum(file):
    # read checksum
    checksum = file.read(CHECKSUM_SIZE)
    if len(checksum) < CHECKSUM_SIZE:
        raise ValueError("file contains less data than needed")

    return checksum


def validate_checksum(checksum, metadata, blob):
    # prepare hash
    sha256 = hashlib.sha256()

    # update with metadata
    sha256.update(metadata.salt)
    sha256.update(struct.pack(">LLL", metadata.n, metadata.r, metadata.p))
    sha256.update(metadata.cipher.value.encode().ljust(METADATA_CIPHER_SIZE, b"\x00"))

    # update with metadata blob key
    sha256.update(metadata.blob_key.iv)
    sha256.update(metadata.blob_key.auth_tag)
    sha256.update(metadata.blob_key.key)

    # update with metadata metadata.blob
    sha256.update(metadata.blob.iv)
    sha256.update(metadata.blob.auth_tag)

    # update with metadata padding
    metadata_size = (
        METADATA_SALT_SIZE
        + struct.calcsize(">LLL")
        + METADATA_CIPHER_SIZE
        + METADATA_BLOB_KEY_IV_SIZE
        + METADATA_BLOB_KEY_AUTH_TAG_SIZE
        + METADATA_BLOB_KEY_KEY_SIZE
        + METADATA_BLOB_IV_SIZE
        + METADATA_BLOB_AUTH_TAG_SIZE
    )
    sha256.update(bytes(METADATA_SIZE - metadata_size))

    # update with blob
    sha256.update(struct.pack(">L", len(blob)))
    sha256.update(blob)

    # make digest
    digest = sha256.digest()

    # compare
    if checksum != digest:
        raise ValueError("file corrupted - checksum validation failed")


# metadata


def read_metadata(file):
    # prepare structs
    partial_metadata_struct = Struct(">" + str(METADATA_SALT_SIZE) + "sLLL" + str(METADATA_CIPHER_SIZE) + "s")
    blob_key_struct = Struct(
        ">"
        + str(METADATA_BLOB_KEY_IV_SIZE)
        + "s"
        + str(METADATA_BLOB_KEY_AUTH_TAG_SIZE)
        + "s"
        + str(METADATA_BLOB_KEY_KEY_SIZE)
        + "s"
    )
    blob_struct = Struct(">" + str(METADATA_BLOB_IV_SIZE) + "s" + str(METADATA_BLOB_AUTH_TAG_SIZE) + "s")

    # read whole metadata space
    file = BytesIO(file.read(METADATA_SIZE))

    # read partial metadata
    partial_metadata = file.read(partial_metadata_struct.size)
    if len(partial_metadata) < partial_metadata_struct.size:
        raise ValueError("file contains less data than needed")
    partial_metadata = partial_metadata_struct.unpack(partial_metadata)

    # read blob key
    blob_key = file.read(blob_key_struct.size)
    if len(blob_key) < blob_key_struct.size:
        raise ValueError("file contains less data than needed")
    blob_key = blob_key_struct.unpack(blob_key)
    blob_key = Metadata.BlobKey(*blob_key)

    # read blob
    blob = file.read(blob_struct.size)
    if len(blob) < blob_struct.size:
        raise ValueError("file contains less data than needed")
    blob = blob_struct.unpack(blob)
    blob = Metadata.Blob(*blob)

    # make metadata
    metadata = Metadata(*partial_metadata, blob_key, blob)

    return metadata


# blob


def read_blob(file):
    # prepare structs
    size_struct = Struct(">L")

    # read size
    size = file.read(size_struct.size)
    if len(size) < size_struct.size:
        raise ValueError("file contains less data than needed")
    (size,) = size_struct.unpack(size)

    # read blob
    blob = file.read(size)
    if len(blob) < size:
        raise ValueError("file contains less data than needed")

    return blob


# file


def read_file(file):
    # read header
    header = read_header(file)

    # validate header values
    if header.magic != HEADER_MAGIC:
        raise ValueError("not a SECO file")
    if (header.version != HEADER_VERSION) or (header.version_tag != HEADER_VERSION_TAG):
        raise ValueError("unsupported version")

    # read checksum
    checksum = read_checksum(file)

    # read metadata
    metadata = read_metadata(file)

    # read blob
    blob = read_blob(file)

    # validate digest
    validate_checksum(checksum, metadata, blob)

    # make file
    file = File(header, checksum, metadata, blob)

    return file


# main


if __name__ == "__main__":
    # prepare parser and parse args
    parser = ArgumentParser(description="exodus2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to SECO file")
    args = parser.parse_args()

    try:
        with open(args.path, "rb") as file:
            file = read_file(file)

        hash = ":".join(
            map(
                str,
                [
                    SIGNATURE,
                    file.metadata.n,
                    file.metadata.r,
                    file.metadata.p,
                    b64encode(file.metadata.salt).decode(),
                    b64encode(file.metadata.blob_key.iv).decode(),
                    b64encode(file.metadata.blob_key.key).decode(),
                    b64encode(file.metadata.blob_key.auth_tag).decode(),
                ],
            )
        )
        print(hash)
    except IOError as e:
        parser.error(e.strerror.lower())
    except ValueError as e:
        parser.error(str(e))
