#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [64, 64], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  $salt = pack ("H*", $salt);

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => 100000,
  );

  my $key = $kdf->PBKDF2_hex ($salt, $word);

  my $hash = sprintf ('$pbkdf2-hmac-sha512$100000.%s.%s', unpack ("H*", $salt), $key);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 27) eq '$pbkdf2-hmac-sha512$100000.';

  my (undef, $signature, $tmp) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $tmp;

  my ($iter, $salt) = split '\.', $tmp;

  return unless defined $iter;
  return unless defined $salt;

  return unless $iter == 100000;
  return unless length $salt == 64;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
