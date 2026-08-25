#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# Password Safe v3. The mode is OPTS_TYPE_BINARY_HASHFILE: hashcat is handed a
# .psafe3 file rather than a hash string, and test.sh rebuilds that file by
# base64-decoding what the oracle prints, so what is printed here is the file
# itself in base64.
#
# Only the first 72 bytes of it matter to module_hash_decode:
#
#   "PWS3" || salt(32) || iterations(4, little-endian) || stretched hash(32)
#
# and the key stretch is
#
#   P = SHA256(password || salt), then SHA256 applied `iterations` more times
#   stored hash = SHA256(P)
#
# The rest of a real file is the encrypted database, which hashcat never reads,
# so a random tail stands in for it. The total length matches the module's own
# self-test file at 360 bytes.

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  $iter = 2048 unless defined $iter && $iter > 0;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, base64, hashlib, os, struct

password   = sys.argv[1].encode()
salt       = bytes.fromhex(sys.argv[2])
iterations = int(sys.argv[3])

p = hashlib.sha256(password + salt).digest()
for _ in range(iterations):
    p = hashlib.sha256(p).digest()

header = b"PWS3" + salt + struct.pack("<I", iterations) + hashlib.sha256(p).digest()

psafe3 = header + os.urandom(288)   # tail stands in for the encrypted database

print(base64.b64encode(psafe3).decode())
PYCODE

  my $digest = do {
    local $ENV{PYTHONUTF8} = 1;
    qx{python3 - "$word" "$salt" "$iter" <<'PY'
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

  my $idx = index ($line, ":");

  return if $idx < 1;

  my $hash_in = substr ($line, 0, $idx);
  my $word    = substr ($line, $idx + 1);

  return unless defined $hash_in;
  return unless defined $word;

  my $header = substr (MIME::Base64::decode_base64 ($hash_in), 0, 72);

  return unless length $header == 72;
  return unless substr ($header, 0, 4) eq "PWS3";

  my $salt = unpack ("H*", substr ($header, 4, 32));
  my $iter = unpack ("V",  substr ($header, 36, 4));

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
