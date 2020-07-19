#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word       = shift;
  my $salt       = shift;
  my $iterations = shift // 1000;
  my $out_len    = shift // 24;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iterations,
    output_len => $out_len
  );

  my $digest = encode_base64 ($pbkdf2->PBKDF2 ($salt, $word), "");

  my $base64_salt = encode_base64 ($salt, "");

  my $hash = sprintf ("sha256:%i:%s:%s", $iterations, $base64_salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (/:([^:]+)$/, $line);

  return unless defined $digest;
  return unless defined $word;

  my @data = split (':', $digest);

  return unless scalar (@data) == 4;

  my $signature = shift @data;

  return unless ($signature eq 'sha256');

  my $iterations = int (shift @data);

  my $salt = decode_base64 (shift @data);
  my $hash = decode_base64 (shift @data);

  my $out_len = length ($hash);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iterations, $out_len);

  return ($new_hash, $word);
}

1;
