#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

# GPG symmetric secret-key protection (S2K iterated+salted), AES-128-CFB,
# S2K KDF hash = SHA-256 (this mode). Integrity is a trailing SHA-1 checksum
# over the decrypted data (OpenPGP secret-key usage 254), which is exactly
# what module_17010's check_decoded_data() verifies.
#
# Per-mode knobs (see m17020 = SHA-512, m17030 = SHA-256):
#   S2K_HASH    : the hashlib name for the S2K KDF
#   S2K_HASH_ID : the OpenPGP hash-algorithm id the parser requires in token[7]

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, hashlib
from random import randint
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

S2K_HASH    = "sha256"
S2K_HASH_ID = 8

def s2k_iterated_salted(password: bytes, salt: bytes, count: int, out_len: int, hashname: str) -> bytes:
    # OpenPGP S2K id=3: H_i = HASH( (0x00 * i) || (salt||password streamed to `count` bytes) )
    base = salt + password
    out = bytearray()
    i = 0
    while len(out) < out_len:
        h = hashlib.new(hashname)
        if i:
            h.update(b"\x00" * i)
        remaining = count
        while remaining >= len(base):
            h.update(base); remaining -= len(base)
        if remaining:
            h.update(base[:remaining])
        out.extend(h.digest()); i += 1
    return bytes(out[:out_len])

password    = sys.argv[1].encode()
salt        = get_random_bytes(8)
iv          = get_random_bytes(16)
_c          = randint(0, 96)                 # OpenPGP coded octet -> decoded count in [1024, 65536]
salt_iter   = (16 + (_c & 15)) << ((_c >> 4) + 6)   # a *valid* count real GnuPG would emit
cipher_algo = 7                              # 7 = AES-128 (16-byte key)

key = s2k_iterated_salted(password, salt, salt_iter, 16, S2K_HASH)

# decrypted data = <secret-key material> || SHA1(<secret-key material>)
# (the trailing checksum is SHA-1 regardless of the S2K hash). Keep the total
# a multiple of the 16-byte AES block so block-CFB round-trips cleanly.
body     = get_random_bytes(300)
checksum = hashlib.sha1(body).digest()
plaintext = body + checksum                  # 300 + 20 = 320 bytes

data = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(plaintext)

print(f"$gpg$*1*{len(data)}*1024*{data.hex()}*3*254*{S2K_HASH_ID}*{cipher_algo}*16*{iv.hex()}*{salt_iter}*{salt.hex()}")
PYCODE

  my $digest = do {
    local $ENV{PYTHONUTF8} = 1;
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
