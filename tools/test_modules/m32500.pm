#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# Dogechain.info wallet. The stored string is
#
#   $dogechain$0*<iterations>*<base64 payload>*<base64 salt>
#
# where the payload is a 16-byte IV followed by the AES-256-CBC encrypted
# wallet, 240 bytes in total, and the salt is 16 bytes. The key is
#
#   PBKDF2-HMAC-SHA256(base64(SHA256(password)), salt, iterations, 32)
#
# so the password is hashed and base64'd into a 44-character string before it
# ever reaches PBKDF2.
#
# There is no MAC: the kernel decides a password is right when the decrypted
# wallet is all ASCII. It skips the final block while checking, because the
# padding is ISO 10126, which is random bytes with a length byte at the end and
# would fail an ASCII test on its own. The oracle matches that by making the
# plaintext exactly 208 ASCII bytes, so the padding takes up a whole block of
# its own and every byte the kernel looks at is ASCII.

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  $iter = 5000 unless defined $iter && $iter > 0;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, base64, hashlib, json
from os import urandom
from Crypto.Cipher import AES

password   = sys.argv[1].encode()
salt       = bytes.fromhex(sys.argv[2])
iterations = int(sys.argv[3])

# 208 bytes of printable wallet JSON, so the 224-byte plaintext ends with a
# full block of ISO 10126 padding that the kernel never inspects
guid = urandom(16).hex()
body = json.dumps({"guid": guid, "sharedKey": urandom(16).hex()}, separators=(",", ":"))
body = (body + " " * 208)[:208]

padded = body.encode() + urandom(15) + bytes([16])

key = hashlib.pbkdf2_hmac(
    "sha256",
    base64.b64encode(hashlib.sha256(password).digest()),
    salt,
    iterations,
    32)

iv      = urandom(16)
payload = iv + AES.new(key, AES.MODE_CBC, iv=iv).encrypt(padded)

print("$dogechain$0*%d*%s*%s" % (
    iterations,
    base64.b64encode(payload).decode(),
    base64.b64encode(salt).decode()))
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

  my @data = split ('\*', $hash_in);

  return unless scalar @data == 4;

  my $iter = $data[1];
  my $salt = unpack ("H*", MIME::Base64::decode_base64 ($data[3]));

  return unless length $salt == 32;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
