#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_raw);
use Digest::Keccak   qw (keccak_256_hex);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $scrypt_N   = shift || 1024 ; # 262144 originally
  my $scrypt_r   = shift || 1; # 8 originally
  my $scrypt_p   = shift || 1;
  my $ciphertext = shift || random_bytes (32);

  my $derived_key = scrypt_raw ($word, $salt, $scrypt_N, $scrypt_r, $scrypt_p, 32);

  my $derived_key_cropped = substr ($derived_key, 16, 16);

  my $digest = keccak_256_hex ($derived_key_cropped . $ciphertext);

  my $hash = sprintf ("\$ethereum\$s*%i*%i*%i*%s*%s*%s", $scrypt_N, $scrypt_r, $scrypt_p, unpack ("H*", $salt), unpack ("H*", $ciphertext), $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $signature = substr ($hash, 0, 12);

  return unless ($signature eq "\$ethereum\$s\*");

  my @data = split ('\*', $hash);

  return unless scalar (@data) == 7;

  shift @data;

  my $scrypt_N   = shift @data;
  my $scrypt_r   = shift @data;
  my $scrypt_p   = shift @data;
  my $salt       = pack ("H*", shift @data);
  my $ciphertext = pack ("H*", shift @data);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $scrypt_N, $scrypt_r, $scrypt_p, $ciphertext);

  return ($new_hash, $word);
}

1;
