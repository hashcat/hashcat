#!/usr/bin/env python3

#
# Author......: See docs/credits.txt
# License.....: MIT
#

from argparse import ArgumentParser, ArgumentTypeError


SALT_LENGTH = 64
DATA_LENGTH = 448
HEADER_LENGTH = SALT_LENGTH + DATA_LENGTH

SIGNATURE = "$truecrypt$"

BOOTABLE_OFFSET = 31744  # 62 * 512
HIDDEN_OFFSET = 65536  # 64K


def validate_offset(offset):
    # see also https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_extract_the_hashes_from_truecrypt_volumes
    if offset == "bootable":
        offset = BOOTABLE_OFFSET
    elif offset == "hidden":
        offset = HIDDEN_OFFSET
    elif offset == "bootable+hidden":
        offset = BOOTABLE_OFFSET + HIDDEN_OFFSET
    try:
        offset = int(offset)
    except ValueError as e:
        raise ArgumentTypeError("value is nether number nor allowed string") from e
    if offset < 0:
        raise ArgumentTypeError("value cannot be less than zero")
    return offset


if __name__ == "__main__":
    parser = ArgumentParser(description="truecrypt2hashcat extraction tool")
    parser.add_argument(
        "--offset",
        default=0,
        type=validate_offset,
        required=False,
        help="select between bootable, hidden, bootable+hidden or custom one (default: 0)",
    )
    parser.add_argument("path", type=str, help="path to TrueCrypt container")

    args = parser.parse_args()

    try:
        with open(args.path, "rb") as file:
            file.seek(args.offset)

            header = file.read(HEADER_LENGTH)

        if len(header) < HEADER_LENGTH:
            parser.error("file contains less data than needed")

        salt, data = header[:SALT_LENGTH], header[SALT_LENGTH:]

        hash = SIGNATURE + salt.hex() + "$" + data.hex()
        print(hash)
    except IOError as e:
        parser.error(e.strerror.lower())
