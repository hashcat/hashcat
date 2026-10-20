#!/usr/bin/env python3

# Script to extract the hash for use with hashcat modes 38800 and 38810

#
# Author......: See docs/credits.txt
# License.....: MIT
#

from argparse import ArgumentParser
from hashlib import md5
from os import SEEK_SET
from struct import Struct


# consts


SIGNATURE = "$openbsd-softraid$"

# struct sr_metadata of sys/dev/softraidvar.h is written in the byte order of the machine that
# created the volume, and so is its magic. The magic read in both orders says which one that was.

MAGIC_LE = (0x4d4152436372616d).to_bytes(8, "little")
MAGIC_BE = (0x4d4152436372616d).to_bytes(8, "big")

# softraid(4) reads its metadata 16 blocks of 512 bytes into the partition, so a partition or an
# image of one has it at 8192, and a whole disk has it at some sector boundary further in

SR_META_OFFSET = 16 * 512
SR_META_BYTES = 64 * 512
SECTOR = 512

SR_OPT_CRYPTO = 0x01

SR_CRYPTOM_AES_ECB_256 = 1
SR_CRYPTOC_HMAC_SHA1 = 1

SR_CRYPTOKDFT_PKCS5_PBKDF2 = 1
SR_CRYPTOKDFT_KEYDISK = 2
SR_CRYPTOKDFT_BCRYPT_PBKDF = 3

KDF_NAMES = {
    SR_CRYPTOKDFT_PKCS5_PBKDF2: "PBKDF2, mode 38800",
    SR_CRYPTOKDFT_BCRYPT_PBKDF: "bcrypt_pbkdf, mode 38810",
}

# a version 5 metadata block and later chains its optional parts by their own length. Before that
# each was a fixed 2480 bytes with its fields 8 bytes in, which sr_meta_opt_load () converts.

SR_OLD_META_OPT_SIZE = 2480
SR_OLD_META_OPT_OFFSET = 8


# metadata


def layouts(order):
    """
    The structs of sys/dev/softraidvar.h in one byte order: sr_meta_invariant, the rest of
    sr_metadata, sr_meta_opt_hdr, sr_meta_crypto after its header, and the sr_crypto_pbkdf that
    scm_kdfhint holds.
    """

    return dict(
        invariant=Struct(order + "8sII16sIIIIIIq8s16s4sI"),
        metadata=Struct(order + "16s32sIIQq"),
        opt_hdr=Struct(order + "II16s"),
        crypto=Struct(order + "IIII64s2048s256sII64s"),
        kdfhint=Struct(order + "III128s"),
    )


CHUNK_SIZE = 92


class NotHere(Exception):
    """
    Raised where the metadata is not, so the next place can be tried.
    """


def decode(block):
    """
    Decode the CRYPTO metadata of one softraid metadata block. Raise NotHere where there is no
    softraid metadata, and ValueError where there is but no passphrase opens it.
    """

    if block[:8] == MAGIC_LE:
        order = "<"
    elif block[:8] == MAGIC_BE:
        order = ">"
    else:
        raise NotHere("no softraid magic")

    s = layouts(order)

    # a file can end right after a sector that only happens to start with the magic

    if len(block) < (s["invariant"].size + s["metadata"].size):
        raise NotHere("the file ends inside the metadata")

    invariant = block[:s["invariant"].size]

    (_, version, _, _, chunk_no, _, opt_no, _, _, _, _, _, product, _, _) = s["invariant"].unpack(invariant)

    checksum = s["metadata"].unpack_from(block, s["invariant"].size)[0]

    # sr_meta_validate () refuses metadata whose invariant part does not match its MD5, which also
    # rules out a sector that only happens to start with the magic

    if md5(invariant).digest() != checksum:
        raise NotHere("the metadata's own MD5 does not match")

    # the optional parts follow sr_metadata and one sr_meta_chunk per chunk, as sr_meta_opt_load ()
    # walks them

    pos = s["invariant"].size + s["metadata"].size + (chunk_no * CHUNK_SIZE)

    for _ in range(opt_no):
        if (pos + s["opt_hdr"].size) > len(block):
            break

        som_type, som_length, _ = s["opt_hdr"].unpack_from(block, pos)

        if som_length == 0:
            body = pos + SR_OLD_META_OPT_OFFSET
            step = SR_OLD_META_OPT_SIZE
        else:
            body = pos + s["opt_hdr"].size
            step = som_length

        if som_type == SR_OPT_CRYPTO:
            if (body + s["crypto"].size) > len(block):
                raise ValueError("the CRYPTO metadata runs past the end of the metadata block")

            fields = crypto_fields(s, block, body)

            fields.update(version=version, order="little" if order == "<" else "big")

            return fields

        if step == 0:
            break

        pos += step

    raise ValueError("softraid metadata, but not of a CRYPTO volume (product %r)"
                     % product.split(b"\0", 1)[0].decode("ascii", "replace"))


def crypto_fields(s, block, body):
    """
    Read the fields of sr_meta_crypto that the hash needs, or raise ValueError where no
    passphrase can open the volume.
    """

    alg, flags, mask_alg, _, _, keys, kdfhint, check_alg, _, chk = s["crypto"].unpack_from(block, body)

    # sr_crypto_decrypt_key () unmasks the keys only with AES-256-ECB and checks them only with
    # HMAC-SHA1. Whether the data is AES-XTS-128 or -256 takes no part in that.

    if mask_alg != SR_CRYPTOM_AES_ECB_256:
        raise ValueError("key masking algorithm %d is not AES-256-ECB" % mask_alg)

    if check_alg != SR_CRYPTOC_HMAC_SHA1:
        raise ValueError("key check algorithm %d is not HMAC-SHA1" % check_alg)

    _, kdf, rounds, salt = s["kdfhint"].unpack(kdfhint[:s["kdfhint"].size])

    if kdf == SR_CRYPTOKDFT_KEYDISK:
        raise ValueError("the volume opens with a key disk, not with a passphrase")

    if kdf not in KDF_NAMES:
        raise ValueError("KDF type %d is not one bioctl(8) writes for a passphrase" % kdf)

    if rounds == 0:
        raise ValueError("the KDF hint holds no round count")

    return dict(alg=alg, kdf=kdf, rounds=rounds, salt=salt, keys=keys, chk=chk[:20])


def candidates(file):
    """
    The offsets where softraid metadata may start: a partition's offset first, then every sector
    of the file that starts with the magic, in either byte order, in file order.
    """

    yield SR_META_OFFSET

    # a disk image: the magic sits at a sector boundary, and a read of whole sectors never splits
    # it across two reads

    base = 0

    while True:
        file.seek(base, SEEK_SET)

        data = file.read(1024 * 1024)

        if len(data) == 0:
            return

        hits = []

        for magic in (MAGIC_LE, MAGIC_BE):
            hit = data.find(magic)

            while hit != -1:
                if (hit % SECTOR) == 0:
                    hits.append(base + hit)

                hit = data.find(magic, hit + 1)

        for hit in sorted(hits):
            yield hit

        base += len(data)


def read_metadata(file, offset):
    """
    Give back the CRYPTO metadata, where it was found and what was passed over on the way, or
    raise ValueError. With no offset, try a partition's offset first, then every sector of the
    file in turn.
    """

    if offset is not None:
        file.seek(offset, SEEK_SET)

        try:
            return decode(file.read(SR_META_BYTES)), offset, []
        except NotHere as e:
            raise ValueError("no softraid metadata at offset %d: %s" % (offset, e))

    # A whole disk can hold other softraid metadata ahead of the volume, such as a RAID 1 chunk,
    # a key disk, or a CRYPTO volume that opens with a key disk. Each is a reason to look further,
    # and the reasons are reported only when no volume a passphrase opens turns up.

    skipped = []
    tried = set()

    for at in candidates(file):
        if at in tried:
            continue

        tried.add(at)

        file.seek(at, SEEK_SET)

        try:
            return decode(file.read(SR_META_BYTES)), at, skipped
        except NotHere:
            continue
        except ValueError as e:
            skipped.append("offset %d: %s" % (at, e))

    if skipped:
        raise ValueError("no CRYPTO volume that opens with a passphrase, only softraid metadata "
                         "it cannot use, at %s" % ", ".join(skipped))

    raise ValueError("no softraid metadata in the file")


def main():
    parser = ArgumentParser(description="openbsd_softraid2hashcat extraction tool")
    parser.add_argument("path", type=str, help="path to a softraid CRYPTO chunk (the RAID "
                                               "partition, such as /dev/rsd0a), or an image of "
                                               "it or of the whole disk")
    parser.add_argument("--offset", type=int, help="byte offset of the metadata, where the "
                                                   "search does not find it")
    parser.add_argument("--verbose", action="store_true", help="say where the metadata was found "
                                                               "and what it carries")
    args = parser.parse_args()

    try:
        with open(args.path, "rb") as file:
            metadata, offset, skipped = read_metadata(file, args.offset)
    except IOError as e:
        parser.error(e.strerror.lower() if e.strerror else str(e))
    except ValueError as e:
        parser.error(str(e))

    if args.verbose:
        for reason in skipped:
            print("# skipped %s" % reason)

        print("# metadata at offset %d, version %d, %s endian, AES-XTS-%d, %s, %d rounds"
              % (offset, metadata["version"], metadata["order"],
                 128 if metadata["alg"] == 1 else 256, KDF_NAMES[metadata["kdf"]],
                 metadata["rounds"]))

    print("%s%d$%s$%s$%s$%d" % (SIGNATURE, metadata["rounds"], metadata["salt"].hex(),
                                metadata["keys"].hex(), metadata["chk"].hex(), metadata["kdf"]))


if __name__ == "__main__":
    main()
