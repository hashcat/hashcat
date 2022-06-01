#!/usr/bin/env python3

from argparse import ArgumentParser, ArgumentTypeError


SALT_LENGTH = 64
DATA_LENGTH = 448
HEADER_LENGTH = SALT_LENGTH + DATA_LENGTH

SIGNATURE = "$veracrypt$"

BOOTABLE_OFFSET = 31744  # 62 * 512
HIDDEN_OFFSET = 65536  # 64K


def validate_offset(offset):
    # see also https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_do_i_extract_the_hashes_from_veracrypt_volumes
    if offset == "bootable":
        offset = BOOTABLE_OFFSET
    elif offset == "hidden":
        offset = HIDDEN_OFFSET
    elif offset == "bootable+hidden":
        offset = BOOTABLE_OFFSET + HIDDEN_OFFSET
    try:
        offset = int(offset)
        assert offset >= 0
    except (AssertionError, ValueError):
        raise ArgumentTypeError("offset is nether non-negative number nor bootable, hidden or bootable+hidden value")
    return offset


if __name__ == "__main__":
    parser = ArgumentParser(description="veracrypt2hashcat extraction tool")
    parser.add_argument(
        "--offset",
        default=0,
        type=validate_offset,
        required=False,
        help="select between bootable, hidden, bootable+hidden or custom one (default: 0)",
    )
    parser.add_argument("path", type=str, help="path to VeraCrypt container")

    args = parser.parse_args()

    with open(args.path, "rb") as file:
        file.seek(args.offset)

        header = file.read(HEADER_LENGTH)

    assert len(header) == HEADER_LENGTH, "less data than needed"

    salt, data = header[:SALT_LENGTH], header[SALT_LENGTH:]

    hash = SIGNATURE + salt.hex() + "$" + data.hex()
    print(hash)
