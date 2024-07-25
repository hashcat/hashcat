#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => 100000,
  );

  my $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt, $word), "");

  my $salt_buf = encode_base64 ($salt, "");

  # replace + with .
  $hash_buf =~ s/\+/\./g;
  $salt_buf =~ s/\+/\./g;

  # remove padding =
  $hash_buf =~ s/\=+$//;
  $salt_buf =~ s/\=+$//;

  my $hash = sprintf ('$pbkdf2-sha256$100000$%s$%s', $salt_buf, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 22) eq '$pbkdf2-sha256$100000$';

  my (undef, $signature, $iter, $salt) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $iter;
  return unless defined $salt;

  return unless $iter == 100000;
  return unless length $salt == 43;

  $salt =~ s/\./\+/g;
  $salt .= '==';

  my $salt_b64 = decode_base64 ($salt);

  return unless length $salt_b64 == 32;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt_b64);

  return ($new_hash, $word);
}

1;
