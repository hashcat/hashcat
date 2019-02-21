#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::UnixCrypt_XS qw (crypt_rounds fold_password base64_to_int24 block_to_base64 int24_to_base64);

sub module_constraints { [[1, 31], [4, 4], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // random_number (1, 5000);

  my $key_value = fold_password ($word);

  my $data = "\x00\x00\x00\x00\x00\x00\x00\x00";

  my $salt_value = base64_to_int24 ($salt);

  my $hash_buf = crypt_rounds ($key_value, $iter, $salt_value, $data);

  my $tmp_hash = sprintf ("_%s%s%s", int24_to_base64 ($iter), $salt, block_to_base64 ($hash_buf));

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  return unless (substr ($line, 0, 1) eq '_');

  my $index1 = index ($line, ':', 20);

  return if ($index1 != 20);

  # iter

  my $iter = substr ($line, 1, 4);

  $iter = base64_to_int24 ($iter);

  # salt

  my $salt = substr ($line, 5, 4);

  # word / hash

  my $word = substr ($line, $index1 + 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
