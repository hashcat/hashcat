#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;
  my $out_len    = shift // 20;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iterations,
    output_len => $out_len
  );

  my $digest = $pbkdf2->PBKDF2 ($salt, $word);
  my $digest_hex = unpack "H*", $digest;

  my $hash = sprintf ('pbkdf2(%i,20,sha512)$%s$%s', $iterations, $salt, $digest_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my ($intro, $salt, $hash_encoded) = split ('$', $digest);
  my ($signature, $iterations, $len, $prf) = split (m/[\(\),]/, $digest);

  return unless ($signature eq 'pbkdf2');
  return unless ($prf eq 'sha512');
  return unless defined $iterations;
  return unless defined $hash_encoded;

  my $hash = pack 'H*',$hash_encoded;

  my $out_len = length ($hash);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $out_len);

  return ($new_hash, $word);
}

1;
