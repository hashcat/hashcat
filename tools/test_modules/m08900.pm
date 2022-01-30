#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_hash);
use MIME::Base64     qw (decode_base64);

sub module_constraints { [[0, 256], [1, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $N    = shift // 16384;
  my $r    = shift // 8;
  my $p    = shift // 1;

  my $hash_buf = scrypt_hash ($word, $salt, $N, $r, $p, 32);

  my $hash = sprintf ('%s', $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # scrypt
  return unless (substr ($line, 0, 7) eq 'SCRYPT:');

  # get hash
  my $index1 = index ($line, ":", 7);

  return if $index1 < 1;

  # N
  my $N = substr ($line, 7, $index1 - 7);

  my $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  # r
  my $r = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  $index1 = index ($line, ":", $index2 + 1);

  return if $index1 < 1;

  # p
  my $p = substr ($line, $index2 + 1, $index1 - $index2 - 1);

  $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  # salt
  my $salt = substr ($line, $index1 + 1, $index2 - $index1 - 1);

  $salt = decode_base64 ($salt);

  $index1 = index ($line, ":", $index2 + 1);

  return if $index1 < 1;

  # digest

  my $word = substr ($line, $index1 + 1);

  return unless defined $salt;
  return unless defined $word;
  return unless defined $N;
  return unless defined $r;
  return unless defined $p;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $N, $r, $p);

  return ($new_hash, $word);
}

1;
