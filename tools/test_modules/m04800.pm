#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [-1, -1], [0, 38], [-1, -1], [-1, -1]] } # 38 = 55 - 16 - 1

sub get_random_md5chap_salt
{
  my $salt_buf = random_bytes (16);

  my $salt = unpack ("H*", $salt_buf);

  $salt .= ":";

  $salt .= unpack ("H*", random_bytes (1));

  return $salt;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  if (length $salt == 0)
  {
    $salt = get_random_md5chap_salt ();
  }

  my $index = rindex ($salt, ":");

  my $saltx  = substr ($salt, 0, $index);
  my $salt_bin  = pack ("H*", $saltx);
  my $chap_sign = substr ($salt, $index + 1);
  my $chap_sign_bin = pack ("H*", $chap_sign);

  my $hash_buf = md5_hex ($chap_sign_bin . $word . $salt_bin);

  my $hash = sprintf ("%s:%s", $hash_buf, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $index2 = index ($line, ":", $index1 + 1);

  return if $index2 < 1;

  my $index3 = index ($line, ":", $index2 + 1);

  return if $index3 < 1;

  my $salt = substr ($line, $index1 + 1, $index3 - $index1 - 1);

  my $word = substr ($line, $index3 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
