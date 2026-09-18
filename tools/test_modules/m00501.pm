#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Crypt::PasswdMD5;
use MIME::Base64 qw (encode_base64);

# Juniper IVE stores an ordinary md5crypt hash, with the salt always the
# literal "danastre", inside an AES-128-CBC blob under a key baked into the
# product. The stored string is base64 of a 12-byte IV followed by 64 bytes of
# ciphertext, and the plaintext is the 34-character md5crypt string zero-padded
# out to the block size.
#
# The key is the four constants module_00501.c byte-swaps back, read as
# big-endian words, and the IV the cipher actually uses is those 12 bytes
# followed by four zero bytes, because juniper_decrypt_hash() copies 12 bytes
# into a 16-byte buffer it had zeroed.

my $JUNIPER_KEY  = pack ("H*", "a6707a7e8df91059dea70ae52f9c2442");
my $JUNIPER_SALT = "danastre";

# There is no salt in the stored string, so the 12-byte IV takes the salt slot:
# 24 hex characters, which is what test.pl's numeric salt happens to be.
sub module_constraints { [[0, 256], [24, 24], [0, 15], [24, 24], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $iv_hex = shift;

  if (! defined $iv_hex || length $iv_hex != 24)
  {
    $iv_hex = random_hex_string (24);
  }

  my $iv = pack ("H*", $iv_hex);

  my $md5crypt = unix_md5_crypt ($word, $JUNIPER_SALT);

  # 34 bytes of md5crypt in a 64-byte plaintext, zero-padded
  my $plain = $md5crypt . ("\x00" x (64 - length ($md5crypt)));

  my $cipher = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $JUNIPER_KEY,
    iv          => $iv . ("\x00" x 4),
    literal_key => 1,
    header      => "none",
    padding     => "none",
    keysize     => 16
  });

  my $data = $iv . $cipher->encrypt ($plain);

  my $hash = encode_base64 ($data, "");

  return $hash;
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

  my $data = MIME::Base64::decode_base64 ($hash_in);

  return unless length $data == 76;

  my $iv = unpack ("H*", substr ($data, 0, 12));

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $iv);

  return ($new_hash, $word);
}

1;
