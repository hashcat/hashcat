#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::HMAC qw (hmac_hex);
use Digest::SHA  qw (sha256);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub get_random_cloudkeychain_salt
{
  my $salt_buf = random_bytes (16 + 304);

  my $ret = unpack ("H*", $salt_buf);

  return $ret;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 40000;

  if (length $salt == 0)
  {
    $salt = get_random_cloudkeychain_salt ();
  }

  my $salt_hex = substr ($salt, 0, 32);
  my $salt_bin = pack   ("H*", $salt_hex);

  my $data_hex = substr ($salt, 32);
  my $data_bin = pack   ("H*", $data_hex);

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter
  );

  my $key = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $hash_buf = hmac_hex ($data_bin, substr ($key, 32, 32), \&sha256, 64);

  my $hash = sprintf ("%s:%s:%d:%s", $hash_buf, $salt_hex, $iter, $data_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my @datas = split (":", $line);

  return if scalar @datas < 4;

  my $hash = shift @datas;

  my $salt = shift @datas;
  my $iter = shift @datas;
  my $data = shift @datas;

  $salt .= $data;

  my $word = join (":", @datas);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
