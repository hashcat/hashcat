#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::Keccak qw (keccak_256_hex);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift || 1024; # 262144 originally
  my $ciphertext = shift || random_bytes (32);

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    out_len    => 32
  );

  my $derived_key = $pbkdf2->PBKDF2 ($salt, $word);

  my $derived_key_cropped = substr ($derived_key, 16, 16);

  my $digest = keccak_256_hex ($derived_key_cropped . $ciphertext);

  my $hash = sprintf ("\$ethereum\$p*%i*%s*%s*%s", $iterations, unpack ("H*", $salt), unpack ("H*", $ciphertext), $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 12);

  return unless ($signature eq "\$ethereum\$p\*");

  my @data = split ('\*', $hash);

  return unless scalar (@data) == 5;

  shift @data;

  my $iterations = shift @data;
  my $salt       = pack ("H*", shift @data);
  my $ciphertext = pack ("H*", shift @data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $ciphertext);

  return ($new_hash, $word);
}

1;
