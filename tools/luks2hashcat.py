#!/usr/bin/env python3

#
# Author......: See docs/credits.txt
# License.....: MIT
#

from argparse import ArgumentParser
from collections import namedtuple
from dataclasses import dataclass
from os import SEEK_SET
from struct import Struct
from typing import List

try:
    from enum import auto, IntEnum, StrEnum
except ImportError:
    from enum import auto, Enum, IntEnum

    class StrEnum(str, Enum):
        def _generate_next_value_(name, start, count, last_values):
            return name.lower()

        __str__ = str.__str__

        __format__ = str.__format__


# consts


SIGNATURE = "$luks$"
SECTOR_SIZE = 512


# utils


def bytes_to_str(value):
    """
    Convert encoded padded bytes string into str.
    """
    return value.rstrip(b"\0").decode()


# pre-header


TmpHeaderPre = namedtuple(
    "TmpHeaderPre",
    (
        "magic",
        "version",
    ),
)


# version 1


TmpKeyVersion1 = namedtuple(
    "TmpKeyVersion1",
    (
        "active",
        "iterations",
        "salt",
        "material_offset",
        "stripes",
    ),
)


@dataclass(init=False)
class KeyVersion1:
    class Active(IntEnum):
        ENABLED = 0x00AC71F3
        DISABLED = 0x0000DEAD
        ENABLED_OLD = 0xCAFE
        DISABLED_OLD = 0x0000

    active: Active
    iterations: int
    salt: bytes
    af: bytes

    def __init__(self, active, iterations, salt, af):
        self.active = self.Active(active)
        if (self.active in [self.Active.ENABLED, self.Active.ENABLED_OLD]) and (iterations <= 0):
            raise ValueError("key iterations cannot be less than zero")
        self.iterations = iterations
        self.salt = salt
        self.af = af


TmpHeaderVersion1 = namedtuple(
    "TmpHeaderVersion1",
    (
        "magic",
        "version",
        "cipher",
        "mode",
        "hash",
        "payload_offset",
        "key_bytes",
        "digest",
        "salt",
        "iterations",
        "uuid",
        "keys",
    ),
)


@dataclass(init=False)
class HeaderVersion1:
    MAGIC = b"LUKS\xba\xbe"
    VERSION = 0x0001

    class Cipher(StrEnum):
        AES = auto()
        TWOFISH = auto()
        SERPENT = auto()

    class Mode(StrEnum):
        CBC_ESSIV_SHA256 = "cbc-essiv:sha256"
        CBC_PLAIN = "cbc-plain"
        CBC_PLAIN64 = "cbc-plain64"
        XTS_PLAIN = "xts-plain"
        XTS_PLAIN64 = "xts-plain64"

    class Hash(StrEnum):
        RIPEMD160 = auto()
        SHA1 = auto()
        SHA256 = auto()
        SHA512 = auto()
        WHIRLPOOL = auto()

    class KeySize(IntEnum):
        SIZE_128 = 128
        SIZE_256 = 256
        SIZE_512 = 512

    magic: bytes
    version: int
    cipher: Cipher
    mode: Mode
    hash: Hash
    payload: bytes
    key_size: KeySize
    digest: bytes
    salt: bytes
    iterations: int
    uuid: str
    keys: List[KeyVersion1]

    def __init__(self, magic, version, cipher, mode, hash, payload, key_size, digest, salt, iterations, uuid, keys):
        if magic != self.MAGIC:
            raise ValueError("invalid magic bytes")
        self.magic = magic
        if version != self.VERSION:
            raise ValueError("invalid version")
        self.version = version
        if isinstance(cipher, bytes):
            try:
                cipher = bytes_to_str(cipher)
                self.cipher = self.Cipher(cipher)
            except UnicodeDecodeError as e:
                raise ValueError("cannot decode cipher") from e
            except ValueError as e:
                raise ValueError("invalid cipher value") from e
        if isinstance(mode, bytes):
            try:
                mode = bytes_to_str(mode)
                self.mode = self.Mode(mode)
            except UnicodeDecodeError as e:
                raise ValueError("cannot decode mode") from e
            except ValueError as e:
                raise ValueError("invalid mode value") from e
        if isinstance(hash, bytes):
            try:
                hash = bytes_to_str(hash)
                self.hash = self.Hash(hash)
            except UnicodeDecodeError as e:
                raise ValueError("cannot decode hash") from e
            except ValueError as e:
                raise ValueError("invalid hash value") from e
        self.payload = payload
        try:
            self.key_size = self.KeySize(key_size)
        except ValueError as e:
            raise ValueError("invalid key size provided") from e
        self.digest = digest
        self.salt = salt
        try:
            iterations = int(iterations)
        except ValueError as e:
            raise ValueError("iterations is not a number") from e
        if iterations <= 0:
            raise ValueError("iterations cannot be less or equal to zero")
        self.iterations = iterations
        if isinstance(uuid, bytes):
            try:
                uuid = bytes_to_str(uuid)
            except UnicodeDecodeError as e:
                raise ValueError("cannot decode UUID") from e
        self.uuid = uuid
        if all(isinstance(key, tuple) for key in keys):
            keys = [KeyVersion1(*key) for key in keys]
        elif all(isinstance(key, dict) for key in keys):
            keys = [KeyVersion1(**key) for key in keys]
        if any(not isinstance(key, KeyVersion1) for key in keys):
            raise ValueError("not a key object provided")
        self.keys = keys


def extract_version1(file):
    # consts
    KEYS_COUNT = 8
    PADDING_LENGTH = 432
    PAYLOAD_SIZE = 512  # sizeof (u32) * 128

    # prepare structs
    key_struct = Struct(">LL32sLL")
    header_struct = Struct(
        ">6sH32s32s32sLL20s32sL40s" + str(key_struct.size * KEYS_COUNT) + "s" + str(PADDING_LENGTH) + "x"
    )

    # read header
    header = file.read(header_struct.size)
    if len(header) < header_struct.size:
        raise ValueError("file contains less data than needed")

    # convert bytes into temporary header
    header = header_struct.unpack(header)
    header = TmpHeaderVersion1(*header)

    # convert bytes into temporary keys
    tmp_keys = [TmpKeyVersion1(*key) for key in key_struct.iter_unpack(header.keys)]

    # read keys' af
    keys = []
    for key in tmp_keys:
        file.seek(key.material_offset * SECTOR_SIZE, SEEK_SET)
        af = file.read(header.key_bytes * key.stripes)
        if len(af) < (header.key_bytes * key.stripes):
            raise ValueError("file contains less data than needed")

        key = KeyVersion1(key.active, key.iterations, key.salt, af)
        keys.append(key)

    # read payload
    file.seek(header.payload_offset * SECTOR_SIZE, SEEK_SET)
    payload = file.read(PAYLOAD_SIZE)
    if len(payload) < PAYLOAD_SIZE:
        raise ValueError("file contains less data than needed")

    # convert into header
    header = HeaderVersion1(
        header.magic,
        header.version,
        header.cipher,
        header.mode,
        header.hash,
        payload,
        header.key_bytes * 8,
        header.digest,
        header.salt,
        header.iterations,
        header.uuid,
        keys,
    )

    # check for any active key
    for key in header.keys:
        if key.active not in [KeyVersion1.Active.ENABLED, KeyVersion1.Active.ENABLED_OLD]:
            continue

        hash = SIGNATURE + "$".join(
            map(
                str,
                [
                    header.version,
                    header.hash,
                    header.cipher,
                    header.mode,
                    int(header.key_size),
                    key.iterations,
                    key.salt.hex(),
                    key.af.hex(),
                    header.payload.hex(),
                ],
            )
        )
        print(hash)
        break
    else:
        # all keys are disabled
        raise ValueError("all keys are disabled")


# main


if __name__ == "__main__":
    # prepare parser and parse args
    parser = ArgumentParser(description="luks2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to LUKS container")
    args = parser.parse_args()

    # prepare struct
    header_struct = Struct(">6sH")

    try:
        with open(args.path, "rb") as file:
            # read pre header
            header = file.read(header_struct.size)
            if len(header) < header_struct.size:
                parser.error("file contains less data than needed")

            # convert bytes into temporary pre header
            header = header_struct.unpack(header)
            header = TmpHeaderPre(*header)

            # check magic bytes
            magic_bytes = {
                HeaderVersion1.MAGIC,
            }
            if header.magic not in magic_bytes:
                parser.error("improper magic bytes")

            # back to start of the file
            file.seek(0, SEEK_SET)

            # extract with proper function
            try:
                mapping = {
                    HeaderVersion1.VERSION: extract_version1,
                }
                extract = mapping[header.version]
                extract(file)
            except KeyError as e:
                raise ValueError("unsupported version") from e
    except IOError as e:
        parser.error(e.strerror.lower())
    except ValueError as e:
        parser.error(str(e))
