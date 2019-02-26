#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::SHA qw (sha512_hex);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $iterations = 4096;

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512);

  my $pbkdf2 = Crypt::PBKDF2->new (
    hasher       => $hasher,
    iterations   => $iterations,
    output_len   => 64
  );

  my $salt_bin = pack ("H*", $salt);

  my $key = $pbkdf2->PBKDF2 ($salt_bin. "AUTH_PBKDF2_SPEEDY_KEY", $word);

  my $digest = sha512_hex ($key . $salt_bin);

  my $hash = sprintf ("%s%s", uc ($digest), uc ($salt));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:/, $line);

  return unless defined $digest;
  return unless length ($digest) == 160;
  return unless defined $word;

  my $salt = substr ($digest, 128, 32);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
