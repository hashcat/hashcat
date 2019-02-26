#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64);

sub module_constraints { [[0, 256], [0, 15], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 10000;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter
  );

  my $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt, $word), "");

  my $hash = sprintf ("pbkdf2_sha256\$%i\$%s\$%s", $iter, $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Django (PBKDF2-SHA256)
  return unless (substr ($line, 0, 14) eq 'pbkdf2_sha256$');

  # get hash
  my $index1 = index ($line, "\$", 14);

  return if $index1 < 1;

  my $index2 = index ($line, "\$", $index1 + 1);

  # iter

  my $iter = substr ($line, 14,  $index1 - 14);

  # salt

  my $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

  # digest

  $index1 = index ($line, ":", $index2 + 1);

  return if $index1 < 1;

  my $word = substr ($line, $index1 + 1);

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
