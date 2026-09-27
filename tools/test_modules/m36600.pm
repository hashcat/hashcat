#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::PBKDF2;
use Encode;

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iterations,
    output_len => 64
  );

  my $digest = encode_base64 ($pbkdf2->PBKDF2 ($salt, encode ("UTF-16LE", $word)), "");

  my $base64_salt = encode_base64 ($salt, "");

  my $hash = sprintf ("sha512utf16le:%i:%s:%s", $iterations, $base64_salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my ($signature, $iterations, $salt_encoded, $hash_encoded) = split (':', $digest);

  return unless ($signature eq 'sha512utf16le');
  return unless defined $iterations;
  return unless defined $salt_encoded;
  return unless defined $hash_encoded;

  my $salt = decode_base64 ($salt_encoded);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations);

  return ($new_hash, $word);
}

1;
