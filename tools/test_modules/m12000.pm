#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use MIME::Base64 qw (encode_base64 decode_base64);
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // random_number (100, 10000);

  my $kdf = Crypt::PBKDF2->new
  (
    hash_class => 'HMACSHA1',
    iterations => $iter,
    output_len => 16
  );

  my $key = $kdf->PBKDF2 ($salt, $word);

  my $key_b64 = encode_base64 ($key, "");

  my $salt_b64 = encode_base64 ($salt, "");

  my $hash = sprintf ("sha1:%i:%s:%s", $iter, $salt_b64, $key_b64);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 5) eq 'sha1:');

  # iterations
  my $index1 = index ($line, ":", 5);

  return if $index1 < 1;

  my $iter = substr ($line, 5, $index1 - 5);

  # salt

  my $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  my $salt = substr ($line, $index1 + 1,  $index2 - $index1 - 1);

  $salt = decode_base64 ($salt);

  # end of digest

  $index1 = index ($line, ":", $index2 + 1);

  return if $index1 < 1;

  # word / hash

  my $word = substr ($line, $index1 + 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
