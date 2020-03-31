#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256);
use Crypt::Mode::ECB;
use Encode;

sub module_constraints { [[4, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

my $ITER     = 1048576; # 0x100000
my $SALT_LEN = 16;
my $IV_LEN   = 12;
my $MAC_LEN  = 16;
my $VMK_LEN  = 44; # note: MAC_LEN + VMK_LEN = 60

sub bitlocker_kdf
{
  my $initial_hash = shift;
  my $salt         = shift;

  # password_key_data (88 bytes):
  #  0-31 (32): last_hash
  # 32-63 (32): init_hash
  # 64-79 (16): salt
  # 80-87 ( 8): iter

  my $password_key_data = "\x00" x (32 + 32 + 16 + 8);

  substr ($password_key_data, 32, 32) = $initial_hash;
  substr ($password_key_data, 64, 16) = $salt;

  for (my $iter = 0; $iter < 0x100000; $iter++)
  {
    substr ($password_key_data, 80,  8) = pack ("Q", $iter);

    substr ($password_key_data,  0, 32) = sha256 ($password_key_data);
  }

  return substr ($password_key_data, 0, 32); # AES-CCM key
}

# non-standard/variant of AES-CCM (encrypt or decrypt, both => crypt):

sub bitlocker_crypt_data
{
  my $key  = shift;
  my $data = shift;
  my $iv   = shift;

  my $ret = ""; # return value (output buffer)

  my $iiv = "\x02"; # 15 - length ($iv) - 1 = 14 - length ($iv)

  $iiv = $iiv . $iv . "\x00\x00\x00"; # add "\x00" x (16 - length ($iv))

  # we could do this in a loop (but let's unroll it to make it clear what is going on):
  # (first and last are special)

  # 0

  # substr ($iiv, 15, 1) = "\x00";

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $block = $aes->encrypt ($iiv, $key);

  for (my $i = 0; $i < 16; $i++)
  {
    $ret .= chr (ord (substr ($data, $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 1

  substr ($iiv, 15, 1) = "\x01";

  $block = $aes->encrypt ($iiv, $key);

  for (my $i = 0; $i < 16; $i++)
  {
    $ret .= chr (ord (substr ($data, 16 + $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 2

  substr ($iiv, 15, 1) = "\x02";

  $block = $aes->encrypt ($iiv, $key);

  for (my $i = 0; $i < 16; $i++)
  {
    $ret .= chr (ord (substr ($data, 32 + $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 3 (final/remaining data: 12 bytes):

  substr ($iiv, 15, 1) = "\x03";

  $block = $aes->encrypt ($iiv, $key);

  for (my $i = 0; $i < 12; $i++)
  {
    $ret .= chr (ord (substr ($data, 48 + $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  return $ret;
}

sub bitlocker_generate_mac
{
  my $key  = shift;
  my $data = shift;
  my $iv   = shift;

  my $iiv = "\x3a" . $iv . "\x00\x00" . "\x2c";

  # we could do this in a loop (but let's unroll it to make it clear what is going on):
  # (first and last are special)

  # 0

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $block = $aes->encrypt ($iiv, $key);

  my $res = "";

  for (my $i = 0; $i < 16; $i++)
  {
    $res .= chr (ord (substr ($data, $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 1

  $block = $aes->encrypt ($res, $key);

  $res = "";

  for (my $i = 0; $i < 16; $i++)
  {
    $res .= chr (ord (substr ($data, 16 + $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 2

  $block = $aes->encrypt ($res, $key);

  $res = "";

  for (my $i = 0; $i < 12; $i++)
  {
    $res .= chr (ord (substr ($data, 32 + $i, 1)) ^ ord (substr ($block, $i, 1)));
  }

  # 3

  $block = $aes->encrypt ($res . substr ($block, 12, 4), $key);

  return $block;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift // random_bytes (12);
  my $data = shift; # if not set, we're going to "generate"/fake it below
  my $type = shift // random_number (0, 1); # if set to 1: check also the MAC in hashcat


  # key generation (KDF):

  my $word_utf16le = encode ("UTF-16LE", $word);

  my $pass_hash = sha256 (sha256 ($word_utf16le));

  my $key = bitlocker_kdf ($pass_hash, $salt);


  if (! $data)
  {
    $data  = pack ("H*", "2c000000"); # actually, only 0x2c00 can be expected for sure
    $data .= pack ("H*", "01000000"); # actually, only 0x0100 can be expected for sure
    $data .= chr (random_number (0, 5));
    $data .= pack ("H*", "200000");   # actually, only 0x20 can be expected for sure

    $data .= random_bytes (44 - 12); # 44 - bytes that we set above
  }
  else
  {
    # verification:

    my $dec_data = bitlocker_crypt_data ($key, $data, $iv); # decryption

    my $data_size = ord (substr ($dec_data, 16, 1)) | (ord (substr ($dec_data, 17, 1)) << 8);
    my $version   = ord (substr ($dec_data, 20, 1)) | (ord (substr ($dec_data, 21, 1)) << 8);

    my $v1 = ord (substr ($dec_data, 16 + 8, 1)); # Volume Master Key (VMK) + 8
    my $v2 = ord (substr ($dec_data, 16 + 9, 1)); # Volume Master Key (VMK) + 9

    # early ejects / failed:

    return unless ($data_size == 0x2c);
    return unless ($version   == 0x01);
    return unless ($v2        == 0x20);
    return unless ($v1        <= 0x05);

    $data = substr ($dec_data, 16); # skip the MAC such that we get only the raw data (VMK etc)

    # note: we do NOT check the $type value ... we do the MAC verification anyway to be safe
    # (for "verify" and $type set to 0 - no MAC verification -, we could early exit here already)
  }


  # MAC (authenticate-then-encrypt, MAC first!):

  my $mac = bitlocker_generate_mac ($key, $data, $iv);


  # encrypt (both, MAC + VMK):

  my $mac_vmk = $mac . $data;

  my $enc_data = bitlocker_crypt_data ($key, $mac_vmk, $iv); # encryption


  # output:

  my $hash = sprintf ("\$bitlocker\$%i\$%i\$%s\$%i\$%i\$%s\$%i\$%s",
    $type,
    $SALT_LEN,
    unpack ("H*", $salt),
    $ITER,
    $IV_LEN,
    unpack ("H*", $iv),
    $MAC_LEN + $VMK_LEN,
    unpack ("H*", $enc_data));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return if ($idx < 0);

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\$', $hash);

  return unless (scalar (@data) == 10);

  my $signature = $data[1];
  my $type      = $data[2];
  my $salt_len  = $data[3];
  my $salt      = $data[4];
  my $iter      = $data[5];
  my $iv_len    = $data[6];
  my $iv        = $data[7];
  my $data_len  = $data[8];
  my $data      = $data[9];

  # sanity checks:

  return unless ($signature eq "bitlocker");

  return unless ($salt_len == $SALT_LEN);
  return unless ($iv_len   == $IV_LEN);
  return unless ($data_len == $MAC_LEN + $VMK_LEN);

  # hex to binary conversion:

  $salt = pack ("H*", $salt);
  $iv   = pack ("H*", $iv);
  $data = pack ("H*", $data);

  return unless (length ($salt) == $SALT_LEN);
  return unless (length ($iv)   == $IV_LEN);
  return unless (length ($data) == $MAC_LEN + $VMK_LEN);


  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iv, $data, $type);

  return ($new_hash, $word);
}

1;
