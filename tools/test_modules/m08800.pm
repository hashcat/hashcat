#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

# Android FDE <= 4.3. The stored string is
#
#   $fde$16$<salt>$16$<encrypted master key>$<1536 bytes of the encrypted disk>
#
# and the chain is
#
#   PBKDF2-HMAC-SHA1(password, salt, 2000, 32) -> key(16) || iv(16)
#   master key = AES-128-CBC-decrypt(encrypted master key, key, iv)
#
# There is no checksum on the master key. The kernel decides a password is
# right by decrypting part of the disk with it and recognizing a filesystem,
# either a FAT boot sector or an ext superblock. This oracle builds the ext
# case, which is the cheaper of the two to construct.
#
# The superblock lives 1024 bytes into the image, and the kernel reads three
# fields out of it: s_first_data_block < 2, s_log_block_size < 16 and
# s_magic == 0xEF53. It gets them by AES-CBC-decrypting bytes 1040 to 1087
# using the 16 bytes ahead of them as the IV, which is a known flaw in the
# implementation (the real IV would be the ESSIV of that sector, so the
# first 16 bytes of the sector never decrypt correctly and the kernel simply
# does not look at them). Encrypting the same way is what makes the fields
# land where the kernel expects.

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $python_code = <<'PYCODE';
#!/usr/bin/env python3
import sys, hashlib, struct
from random import randint
from os import urandom
from Crypto.Cipher import AES

password = sys.argv[1].encode()
salt     = bytes.fromhex(sys.argv[2])

dk  = hashlib.pbkdf2_hmac("sha1", password, salt, 2000, 32)
key = dk[:16]
iv  = dk[16:]

master_key = urandom(16)

enc_master_key = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(master_key)

# bytes 16 to 63 of the ext superblock, the only part the kernel reads
sb = bytearray(urandom(48))
struct.pack_into("<I", sb,  4, randint(0, 1))       # s_first_data_block, must be < 2
struct.pack_into("<I", sb,  8, randint(0, 15))      # s_log_block_size,   must be < 16
struct.pack_into("<H", sb, 40, 0xEF53)              # s_magic

# the 16 bytes ahead of the superblock tail double as its CBC IV
sb_iv = urandom(16)
sb_ct = AES.new(master_key, AES.MODE_CBC, iv=sb_iv).encrypt(bytes(sb))

data = bytearray(urandom(1536))
data[1024:1040] = sb_iv
data[1040:1088] = sb_ct

print("$fde$16$%s$16$%s$%s" % (salt.hex(), enc_master_key.hex(), bytes(data).hex()))
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

  my @data = split ('\$', $hash_in);

  return unless scalar @data == 7;

  my $salt = $data[3];

  return unless length $salt == 32;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
