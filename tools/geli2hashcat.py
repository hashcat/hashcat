#!/usr/bin/env python3

# Script to extract the hash for use with hashcat mode 38700

#
# Author......: See docs/credits.txt
# License.....: MIT
#

from argparse import ArgumentParser
from hashlib import md5
from os import SEEK_END, SEEK_SET
from struct import Struct


# consts


SIGNATURE = "$geli$"

MAGIC = b"GEOM::ELI"

# the metadata is written at the start of the provider's last sector, so a disk or an image is
# searched there for every sector size a provider may have, and a file written by "geli backup"
# holds one sector and starts with it

SECTOR_SIZES = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072)

G_ELI_VERSION = 7

G_ELI_SALTLEN = 64
G_ELI_MKEYLEN = 192
G_ELI_MAXMKEYS = 2

# the encryption algorithms of sys/opencrypto/cryptodev.h that a provider may name, and the two
# geli(4) dropped in FreeBSD 13, which no key length makes readable again

CRYPTO_3DES_CBC = 2
CRYPTO_BLF_CBC = 3
CRYPTO_AES_CBC = 11
CRYPTO_NULL_CBC = 16
CRYPTO_CAMELLIA_CBC = 21
CRYPTO_AES_XTS = 22

EALGO_NAMES = {
    CRYPTO_AES_CBC: "AES-CBC",
    CRYPTO_NULL_CBC: "NULL",
    CRYPTO_CAMELLIA_CBC: "CAMELLIA-CBC",
    CRYPTO_AES_XTS: "AES-XTS",
}

REMOVED_NAMES = {
    CRYPTO_3DES_CBC: "3DES-CBC",
    CRYPTO_BLF_CBC: "Blowfish-CBC",
}

# the key lengths g_eli_keylen () accepts for each algorithm. It also turns a 0 asked for on the
# command line into the algorithm's default, so the metadata on disk always names a real length.

KEYLENS = {
    CRYPTO_AES_CBC: (128, 192, 256),
    CRYPTO_CAMELLIA_CBC: (128, 192, 256),
    CRYPTO_AES_XTS: (128, 256),
}


# metadata


# struct g_eli_metadata of sys/geom/eli/g_eli.h, little endian and packed, with md_aalgo absent
# from version 0

METADATA_V0 = Struct("<16sIIHHQIBi%ds%ds16s" % (G_ELI_SALTLEN, G_ELI_MAXMKEYS * G_ELI_MKEYLEN))
METADATA_V1 = Struct("<16sIIHHHQIBi%ds%ds16s" % (G_ELI_SALTLEN, G_ELI_MAXMKEYS * G_ELI_MKEYLEN))

# md_hash is the MD5 of the header up to itself, and eli_metadata_decode () refuses metadata it
# does not match, which also rules out a sector that only happens to carry the magic

HASHED_LEN_V0 = METADATA_V0.size - 16
HASHED_LEN_V1 = METADATA_V1.size - 16


class NotHere(Exception):
    """
    Raised where the metadata is not, so the next place can be tried.
    """


def decode(sector):
    """
    Decode one metadata sector into its fields. Raise NotHere where the magic is absent, and
    ValueError where the metadata is there but unusable.
    """

    if sector[:16].split(b"\0", 1)[0] != MAGIC:
        raise NotHere("no %s magic" % MAGIC.decode())

    # a slice shorter than the field reads as zero, which the length check below then rejects

    version = int.from_bytes(sector[16:20], "little")

    if version > G_ELI_VERSION:
        raise ValueError("metadata version %d is newer than %d, the highest geli(4) writes"
                         % (version, G_ELI_VERSION))

    layout = METADATA_V0 if version == 0 else METADATA_V1

    if len(sector) < layout.size:
        raise ValueError("the metadata starts here but the file ends inside it")

    fields = layout.unpack(sector[:layout.size])

    if version == 0:
        magic, version, flags, ealgo, keylen, provsize, sectorsize, keys, iterations, salt, mkeys, md5sum = fields
        aalgo = 0
        hashed = HASHED_LEN_V0
    else:
        magic, version, flags, ealgo, keylen, aalgo, provsize, sectorsize, keys, iterations, salt, mkeys, md5sum = fields
        hashed = HASHED_LEN_V1

    if md5(sector[:hashed]).digest() != md5sum:
        raise ValueError("the metadata's own MD5 does not match, so it is not intact")

    return dict(version=version, flags=flags, ealgo=ealgo, keylen=keylen, aalgo=aalgo,
                provsize=provsize, sectorsize=sectorsize, keys=keys, iterations=iterations,
                salt=salt, mkeys=mkeys)


def read_metadata(file):
    """
    Give back the metadata of a provider, an image or a backup file, or raise ValueError.
    """

    size = file.seek(0, SEEK_END)

    # the last sector first, because a provider that was also backed up carries both

    offsets = [size - sectorsize for sectorsize in SECTOR_SIZES if size >= sectorsize]

    if 0 not in offsets:
        offsets.append(0)

    for offset in offsets:
        file.seek(offset, SEEK_SET)

        # the metadata is 511 bytes, and a sector of a provider that carries it is at least 512

        try:
            return decode(file.read(512)), offset
        except NotHere:
            continue

    raise ValueError("no %s metadata in the last sector or at the start of the file" % MAGIC.decode())


def check(metadata):
    """
    Refuse metadata no passphrase can open, saying which part of it is the reason.
    """

    ealgo = metadata["ealgo"]
    keylen = metadata["keylen"]

    if ealgo in REMOVED_NAMES:
        raise ValueError("the provider uses %s, which geli(4) dropped in FreeBSD 13 and no "
                         "longer reads either" % REMOVED_NAMES[ealgo])

    if ealgo not in EALGO_NAMES:
        raise ValueError("encryption algorithm %d is not one geli(4) uses" % ealgo)

    if ealgo == CRYPTO_NULL_CBC:
        if keylen > 64 * 8:
            raise ValueError("key length %d is longer than NULL takes" % keylen)
    elif keylen not in KEYLENS[ealgo]:
        raise ValueError("key length %d is not one %s takes" % (keylen, EALGO_NAMES[ealgo]))

    # g_eli_mkey_decrypt () looks at one bit per slot and ignores the rest of md_keys

    if (metadata["keys"] & ((1 << G_ELI_MAXMKEYS) - 1)) == 0:
        raise ValueError("the metadata holds no master key, so there is nothing to open")

    if metadata["iterations"] == -1:
        raise ValueError("the provider was initialized with -P, so it opens with a keyfile and "
                         "not with a passphrase")

    if metadata["iterations"] < 0:
        raise ValueError("iteration count %d is negative" % metadata["iterations"])


def main():
    parser = ArgumentParser(description="geli2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to a GELI provider, a disk image, or the "
                                               "file written by geli backup")
    parser.add_argument("--verbose", action="store_true", help="say where the metadata was found "
                                                               "and what it carries")
    args = parser.parse_args()

    try:
        with open(args.path, "rb") as file:
            metadata, offset = read_metadata(file)

            check(metadata)
    except IOError as e:
        parser.error(e.strerror.lower() if e.strerror else str(e))
    except ValueError as e:
        parser.error(str(e))

    if args.verbose:
        print("# metadata at offset %d, version %d, %s %d bit, %d iterations, keys 0x%02x, "
              "%d byte sectors"
              % (offset, metadata["version"], EALGO_NAMES[metadata["ealgo"]],
                 metadata["keylen"], metadata["iterations"], metadata["keys"],
                 metadata["sectorsize"]))

    print("%s0$%d$%d$%d$%d$%d$%d$%s$%s" % (SIGNATURE, metadata["version"], metadata["ealgo"],
                                           metadata["keylen"], metadata["aalgo"], metadata["keys"],
                                           metadata["iterations"], metadata["salt"].hex(),
                                           metadata["mkeys"].hex()))


if __name__ == "__main__":
    main()
