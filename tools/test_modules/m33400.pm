#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# mega.nz password-protected link. The link body is base64url of
#
#   algorithm(1) || file/folder(1) || public handle(6) || salt(32) ||
#   encrypted key(16 for a folder, 32 for a file) || MAC tag(32)
#
# and what hashcat verifies is the MAC tag. The key is
# PBKDF2-HMAC-SHA512(password, salt, 100000) taken to 64 bytes: the first half
# decrypts the link key and the second half is the HMAC-SHA256 key over
# everything ahead of the tag. Only algorithm 2 is parsed.
#
# The file/folder byte is picked at random per candidate so that both link
# lengths are exercised, since it decides whether the encrypted key is 16 or
# 32 bytes and therefore how much data the MAC covers.

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, base64, hashlib, hmac
from random import randint
from os import urandom

password = sys.argv[1].encode()
salt     = bytes.fromhex(sys.argv[2])

is_file  = randint(0, 1)                 # 0 = folder (16-byte key), 1 = file (32)
key_len  = 32 if is_file else 16

data  = bytes([2, is_file]) + urandom(6) + salt + urandom(key_len)

dk       = hashlib.pbkdf2_hmac("sha512", password, salt, 100000, 64)
mac_key  = dk[32:]
mac      = hmac.new(mac_key, data, hashlib.sha256).digest()

body = base64.urlsafe_b64encode(data + mac).decode().rstrip("=")

print("P!" + body)
PYCODE

  my $digest = do {
    local $ENV{PYTHONUTF8} = 1;
    qx{python3 - "$word" "$salt" <<'PY'
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

  return unless substr ($hash_in, 0, 2) eq "P!";

  my $body = substr ($hash_in, 2);

  $body =~ tr#-_#+/#;

  my $raw = MIME::Base64::decode_base64 ($body . ("=" x ((4 - length ($body) % 4) % 4)));

  return unless length $raw >= 88;

  my $salt = unpack ("H*", substr ($raw, 8, 32));

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
