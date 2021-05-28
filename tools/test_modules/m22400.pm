#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256);
use Digest::HMAC qw (hmac_hex);
use Encode;

sub module_constraints { [[0, 128], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $iv_aes  = shift // random_bytes (16);
  my $key_aes = shift // random_bytes (32);

  my $word_utf16le = encode ('UTF-16le', $word);

  my $key = $salt . "\x00" x 16;

  for (my $i = 0; $i < 8192; $i++)
  {
    $key = sha256 ($key . $word_utf16le);
  }

  my $digest = hmac_hex ($iv_aes . $key_aes, $key, \&sha256, 64);

  # hex conversion:

  my $salt_hex = unpack ("H*", $salt);
  my $iv_hex   = unpack ("H*", $iv_aes);
  my $key_hex  = unpack ("H*", $key_aes);

  my $hash = sprintf ("\$aescrypt\$1*%s*%s*%s*%s", $salt_hex, $iv_hex, $key_hex, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split ('\*', $hash);

  return unless (scalar (@data) == 5);

  my $signature = substr ($data[0], 0, 10);

  return unless ($signature eq "\$aescrypt\$");

  my $version = substr ($data[0], 10);

  return unless ($version eq "1");

  my $salt = $data[1];
  my $iv   = $data[2];
  my $key  = $data[3];

  return unless (length ($salt) == 32); # hex lengths
  return unless (length ($iv)   == 32);
  return unless (length ($key)  == 64);

  # binary conversion:

  $salt = pack ("H*", $salt);
  $iv   = pack ("H*", $iv);
  $key  = pack ("H*", $key);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iv, $key);

  return ($new_hash, $word);
}

1;
