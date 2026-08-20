#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  # Non-interpolating heredoc: Perl will NOT touch $… or backslashes inside
  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys
from random import randint, choice
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# from Crypto.Hash import SHA1 #hashlib is 8x faster
import hashlib

def s2k_iterated_salted_sha1_decoded(password: bytes, salt: bytes, count: int, out_len: int = 20) -> bytes:
    """
    OpenPGP S2K (ID=3) with SHA-1 using a *decoded* iteration count `count`.
    Produces `out_len` bytes (multiple blocks if >20), with zero-prefixing per RFC 4880.

    H_i = SHA1( (0x00 repeated i) || (salt||password repeated to `count` bytes) )

    Args:
        password: bytes
        salt: 8-byte salt (OpenPGP)
        count: decoded byte count (e.g., 329_368_576)
        out_len: desired output length in bytes

    Returns:
        `out_len` bytes of key material.
    """
    if len(salt) != 8:
        raise ValueError("salt must be exactly 8 bytes (OpenPGP)")

    base = salt + password
    if count < 0:
        raise ValueError("count must be non-negative")
    if out_len <= 0:
        return b""

    out = bytearray()
    i = 0
    while len(out) < out_len:
        h = hashlib.sha1()

        # zero-prefix for block i (only if i>0)
        if i:
            h.update(b"\x00" * i)

        # stream exactly `count` bytes of base into the hash
        remaining = count
        # feed in whole base chunks
        while remaining >= len(base):
            h.update(base)
            remaining -= len(base)
        # and a possible tail
        if remaining:
            h.update(base[:remaining])

        out.extend(h.digest())
        i += 1

    return bytes(out[:out_len])


salt_iter = randint(200_000_000, 300_000_000)
# The 17050 kernel only checks the first decrypted block: "(((1:" <name> <len> ":".
# Exercise every shape it accepts -- RSA and ECC use the secret MPI 'd', DSA/ElGamal
# use 'x', and the length is 2 or 3 ASCII digits depending on key type:
#   ed25519 -> d32   rsa2048 -> d256   ed448 -> d57   dsa/elgamal -> x33
# Only the marker matters to the kernel, so the trailing bytes are just padding.
mpi_name, mpi_len = choice([("d", "32"), ("d", "256"), ("d", "57"), ("x", "33")])
plaintext = ("(((1:%s%s:" % (mpi_name, mpi_len)).encode() + get_random_bytes(51)
salt = get_random_bytes(8)
nonce = get_random_bytes(12)

# password comes from argv[1] (Perl passes $word as the first arg)
password = sys.argv[1]

key = s2k_iterated_salted_sha1_decoded(password.encode(), salt, salt_iter, out_len=16)

cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
ciphertext = cipher.encrypt(plaintext)
ciphertext += cipher.encrypt()
modulus_size=4096
cipher_mode=7 #AES with 128-bit key(sym 7)
print(f"$gpg$*1*{len(ciphertext)}*{modulus_size}*{ciphertext.hex()}*1*254*2*{cipher_mode}*{len(nonce)}*{nonce.hex()}*{salt_iter}*{salt.hex()}")
PYCODE

  # Run python reading program from stdin; pass $word as argv[1]
  my $digest = do {
    # qx here-doc to avoid shell-quoting pitfalls
    local $ENV{PYTHONUTF8} = 1; # optional: force UTF-8 mode
    qx{python3 - "$word" <<'PY'
$python_code
PY
};
  };

  $digest =~ s/[\r\n]//g;

  return $digest;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
