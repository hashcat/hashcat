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
import hashlib, hmac, random, os, sys
from Crypto.Cipher import AES

# password comes from argv[1] (Perl passes $word as the first arg)
password = sys.argv[1]
masterkey = password.encode()

keyfile = os.urandom(32) if random.randint(0, 1) else b""
masterseed = os.urandom(32)
transformseed = os.urandom(32)
iterations = random.randint(20000, 60000)
header = os.urandom(250)


# 1) Composite key: SHA256(SHA256(password) || keyfile)
h1 = hashlib.sha256(password.encode()).digest()
if keyfile and len(keyfile) != 32:
    raise ValueError("keyfile must be 32 bytes")
composite = hashlib.sha256(h1 + keyfile).digest()  # 32B

# 2) AES-KDF: encrypt both 16B halves with AES-256-ECB 'iterations' times
aes = AES.new(transformseed, AES.MODE_ECB)
b0, b1 = composite[:16], composite[16:]

for _ in range(iterations):
    b0 = aes.encrypt(b0)
    b1 = aes.encrypt(b1)
transformed = b0 + b1

# then SHA-256 → DerivedKey (KeePass AES-KDF final)
derived = hashlib.sha256(transformed).digest()  # 32B

# 3) HMAC key material
hmac_key = hashlib.sha512(masterseed + derived + b"\x01").digest()
hdr_key  = hashlib.sha512(b"\xff"*8 + hmac_key).digest()

# 4) Header HMAC
header_hmac = hmac.new(hdr_key, header, hashlib.sha256).hexdigest()


# ------------------------
# Print keepass hash line (AES-KDF UUID c9d9f39a; argon params are 0)
# $keepass$*4*<iterations>*c9d9f39a*0*0*0*<masterseed>*<transformseed>*<header>*<hmac>
# If keyfile present: *1*64*<keyfilehex>
# ------------------------
parts = [
    "$keepass$",
    "4",
    str(iterations),
    "c9d9f39a",         # AES-KDF UUID
    "0",                # memoryUsageInBytes (not used by AES-KDF)
    "0",                # Argon version (unused)
    "0",                # parallelism (unused)
    masterseed.hex(),
    transformseed.hex(),
    header.hex(),
    header_hmac
]
s = "*".join(parts)

if keyfile:
    s += f"*1*64*{keyfile.hex()}"

print(s)
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
