#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_raw);
use Encode;
use Crypt::CBC;

sub module_constraints { [[0, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

my $SCRYPT_N = 16384;
my $SCRYPT_R =     8;
my $SCRYPT_P =     1;

my $DATA_FIXED = "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift // random_bytes (16);
  my $data = shift;

  my $word_utf16be = encode ('UTF-16BE', $word);

  my $key = scrypt_raw ($word_utf16be, $salt, $SCRYPT_N, $SCRYPT_R, $SCRYPT_P, 32);

  my $aes_cbc = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $data_block = "";

  if (defined ($data)) # verify
  {
    my $data_dec = $aes_cbc->decrypt ($data);

    if ($data_dec eq $DATA_FIXED)
    {
      $data_block = $data;
    }
  }
  else
  {
    $data = $DATA_FIXED;

    $data_block = $aes_cbc->encrypt ($data);
  }

  my $hash = sprintf ("\$multibit\$3*%d*%d*%d*%s*%s", $SCRYPT_N, $SCRYPT_R, $SCRYPT_P, unpack ("H*", $salt), unpack ("H*", $iv . $data_block));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 12) eq '$multibit$3*');

  # split hash and word:

  my $idx1 = index ($line, ":", 12);

  return if ($idx1 < 1);

  my $hash = substr ($line,  0, $idx1);
  my $word = substr ($line, $idx1 + 1);

  # scrypt parameters:

  my $idx2 = index ($hash, "*", 12);

  return if ($idx2 < 0);

  my $scrypt_n = substr ($hash, 12, $idx2 - 12);

  $idx1 = index ($hash, "*", $idx2 + 1);

  return if ($idx1 < 0);

  my $scrypt_r = substr ($hash, $idx2 + 1, $idx1 - $idx2 - 1);

  $idx2 = index ($hash, "*", $idx1 + 1);

  return if ($idx2 < 0);

  my $scrypt_p = substr ($hash, $idx1 + 1, $idx2 - $idx1 - 1);

  # salt:

  $idx1 = index ($hash, "*", $idx2 + 1);

  return if ($idx1 < 0);

  my $salt = substr ($hash, $idx2 + 1, $idx1 - $idx2 - 1);

  # IV:

  my $iv = substr ($hash, $idx1 + 1, 32);

  # data:

  my $data = substr ($hash, $idx1 + 1 + 32, 32);

  return unless $salt =~ m/^[0-9a-fA-F]{16}$/;
  return unless $iv   =~ m/^[0-9a-fA-F]{32}$/;
  return unless $data =~ m/^[0-9a-fA-F]{32}$/;

  # hex to binary/raw:

  $salt   = pack ("H*", $salt);
  $iv     = pack ("H*", $iv);
  $data   = pack ("H*", $data);

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iv, $data);

  return ($new_hash, $word);
}

1;
