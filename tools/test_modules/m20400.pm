#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1024;

  if (length $salt == 0)
  {
    $salt = random_bytes (16);
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => $iter
  );

  my $hash_buf = encode_base64 ($pbkdf2->PBKDF2 ($salt, $word), '');
  my $salt_buf = encode_base64 ($salt, '');

  # replace + with .
  $hash_buf =~ s/\+/\./g;
  $salt_buf =~ s/\+/\./g;

  # remove padding =
  $hash_buf =~ s/\=+$//;
  $salt_buf =~ s/\=+$//;

  my $hash = sprintf ("\$pbkdf2\$%i\$%s\$%s", $iter, $salt_buf, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # check signature
  return unless (substr ($line, 0, 15) eq '$pbkdf2$');

  # get hash
  my $index1 = index ($line, '$', 15);

  return if $index1 < 1;

  my $index2 = index ($line, '$', $index1 + 1);

  my $iter = substr ($line, 15,  $index1 - 15);

  my $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

  $index1 = index ($line, ':', $index2 + 1);

  return if $index1 < 1;

  my $word = substr ($line, $index1 + 1);

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  # fix salt from 'alternate' to 'ordinary' base64 encoding before
  $salt =~ s/\./\+/g;
  $salt .= '==';

  my $new_hash = module_generate_hash ($word, decode_base64 ($salt), $iter);

  return ($new_hash, $word);
}

1;
