#!/usr/bin/env python3

import binascii
import sys

try:
    from asn1crypto import pkcs12
except ImportError:
    sys.stderr.write("asn1crypto is missing, run 'pip install asn1crypto' to install it\n")
    sys.exit(1)


def parse_pkcs12(filename):
    data = open(filename, "rb").read()
    pfx = pkcs12.Pfx.load(data)

    auth_safe = pfx['auth_safe']
    if auth_safe['content_type'].native != 'data':
        sys.stderr.write("%s: only password-protected PKCS12 files are supported\n" % filename)
        return

    mac_data = pfx['mac_data']
    if not mac_data:
        sys.stderr.write("%s: no MAC data found in PKCS12 file\n" % filename)
        return

    mac_algo = mac_data['mac']['digest_algorithm']['algorithm'].native

    mac_algo_numeric = {
        'sha1': 1,
        'sha256': 256,
        'sha512': 512,
    }.get(mac_algo)

    if mac_algo_numeric is None:
        sys.stderr.write("%s: unsupported MAC algorithm '%s'\n" % (filename, mac_algo))
        return

    salt = mac_data['mac_salt'].native
    iterations = mac_data['iterations'].native
    stored_hmac = mac_data['mac']['digest'].native
    content_data = auth_safe['content'].contents

    hash_line = "$pkcs12$%s$%s$%s$%s$%s$%s$%s" % (
        mac_algo_numeric,
        iterations,
        len(salt),
        binascii.hexlify(salt).decode(),
        len(content_data),
        binascii.hexlify(content_data).decode(),
        binascii.hexlify(stored_hmac).decode(),
    )

    sys.stdout.write("%s\n" % hash_line)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pfx/.p12 file(s)>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        parse_pkcs12(sys.argv[i])
