#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Digest::MD5 qw (md5);

my $ENC_MAX_KEY_NUM             = 8;
my $ENC_NONCE_SIZE              = 8;
my $ENC_KEY_SIZE                = 16;
my $ENC_BLOCK_SIZE              = 16;
my $ENC_KEYCHAIN_SIZE           = 128;
my $ENC_DEFAULT_MD5_ITERATIONS  = 1000;

my @default_salts =
(
  "\x0f\xc9\xe7\xd0\x8b\xe4\x24\xf6\x56\x9d\x4e\x72\xed\xbc\x2c\x5c",
  "\xdd\x79\x74\xf3\x3d\x83\x00\xc2\x9b\xd2\x93\xd5\x7f\x9d\x9b\x8c",
  "\x60\x85\x0c\x47\x58\x46\xe2\x96\x2d\x99\x5d\x5e\xf1\xd0\x6a\x28",
  "\xe2\x3f\x3d\x6b\x99\x61\x4b\xa9\xc4\xed\xc5\xdd\xd8\x25\x3c\xe1",
  "\x2c\xa4\x59\x89\x1d\x78\x52\xdb\x30\x31\xd0\x9f\x9f\x34\x88\x35",
  "\xdb\x1b\xb5\x27\xe8\x21\x4f\x79\xa0\xb2\xcb\x32\x42\xd9\xf2\x0a",
  "\xae\xa8\xb6\x8e\xd0\x7b\x62\xa1\x40\x0e\x17\xc6\xad\x64\x20\xc8",
  "\xea\xe3\xf4\x4e\xaf\x4a\x8f\x84\xf1\xfa\xb3\x08\x85\x69\xbe\xf8"
);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $algo = shift // random_number (1, 4);
  my $iv   = shift // random_hex_string (16);
  my $ct   = shift;

  # pbkdf2 part

  my $nb_keys = 1 << ($algo - 1);

  my $key_len = $nb_keys * $ENC_KEY_SIZE;

  my $key = "\x00" x 16;

  my $tmp = md5 ($word);

  for (my $i = 1; $i < $ENC_DEFAULT_MD5_ITERATIONS; $i++)
  {
    $tmp = md5 ($tmp);

    $key = xor_len ($key, $tmp, 16);
  }

  my $tmp_key = $key;

  $key = "";

  for (my $i = 0; $i < $ENC_MAX_KEY_NUM; $i++)
  {
    $key .= xor_len ($tmp_key, $default_salts[$i], 16);
  }

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $aes_key = substr ($key, 0, $ENC_KEY_SIZE);

  ## decrypt encrypted data using PBKDF2 key

  my $iv_bin = pack ("H*", $iv);

  my @ivs;

  $ivs[0] = $iv_bin;

  for (my $i = 1; $i < $nb_keys; $i++)
  {
    my $next8 = substr ($key, $i * $ENC_KEY_SIZE, $ENC_NONCE_SIZE); ## its strange to skip 8 byte of key material every 16 byte

    $ivs[$i] = xor_len ($iv_bin, $next8, 8);
  }

  my $ctr_len = 16;

  my $ctr;

  for (my $i = 0, my $counter = 1; $i < ($ctr_len / $ENC_BLOCK_SIZE); $i++, $counter++)
  {
    my $counter_be = pack ("Q>", $counter);

    my $tmp_iv = $ivs[0] . $counter_be;

    my $enc = $aes->encrypt ($tmp_iv, $aes_key);

    my $out = $enc;

    for (my $i = 1; $i < $nb_keys; $i++)
    {
      my $tmp_iv = $ivs[$i] . $counter_be;

      my $enc = $aes->encrypt ($tmp_iv, $aes_key);

      $out = xor_len ($enc, $out, $ENC_BLOCK_SIZE);
    }

    $ctr .= $out;
  }

  my $pt_bin;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    $pt_bin = xor_len (substr ($ctr, 4, 8), $ct_bin, 8);

    # we compare only 56 bit, see https://github.com/hashcat/hashcat/issues/3467

    if (substr ($pt_bin, 0, 7) eq "\xd2\xc3\xb4\xa1\x00\x00\x00")
    {
      # ok
    }
    else
    {
      $pt_bin = "\xff\xff\xff\xff\xff\xff\xff\xff";
    }
  }
  else
  {
    $pt_bin = "\xd2\xc3\xb4\xa1\x00\x00\x00\x30";
  }

  my $ct_bin = xor_len (substr ($ctr, 4, 8), $pt_bin, 8);

  my $hash = sprintf ('$encdv$1$%d$%s$%s', $algo, unpack ("H*", $iv_bin), unpack ("H*", $ct_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 7) eq '$encdv$';

  my (undef, $signature, $version, $algo, $iv, $ct) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $algo;
  return unless defined $iv;
  return unless defined $ct;

  return unless ($version == 1);
  return unless ($algo >= 1);
  return unless ($algo <= 4);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $algo, $iv, $ct);

  return ($new_hash, $word);
}

sub xor_len
{
  my $in1 = shift;
  my $in2 = shift;
  my $len = shift;

  my $out;

  for (my $i = 0; $i < $len; $i++)
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

1;
