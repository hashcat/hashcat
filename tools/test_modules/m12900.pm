#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::HMAC qw (hmac_hex);
use Digest::SHA qw (sha256);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $param = shift;

  my $iterations = 4096;

  my $salt2 = $salt . $salt;

  if (defined $param)
  {
    $salt2 = $param;
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    output_len => 32
  );

  my $salt_bin = pack ("H*", $salt);

  my $tmp = $pbkdf2->PBKDF2 ($salt_bin, $word);

  my $salt2_bin = pack ("H*", $salt2);

  my $hash_hmac = hmac_hex ($salt2_bin, $tmp, \&sha256, 64);

  my $hash = sprintf ("%s%s%s", $salt2, $hash_hmac, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  return unless length $hash_in == 160;

  my $param = substr ($hash_in, 0, 64);
  my $salt  = substr ($hash_in, 128, 32);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param);

  return ($new_hash, $word);
}

1;
