#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5  qw (md5);
use Digest::HMAC qw (hmac_hex);

sub module_constraints { [[0, 256], [116, 148], [0, 55], [0, 31], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_len = length ($salt);

  if ($salt_len < 32) # we don't support salt length > 55 in optimized mode, but this mode requires it
  {
    $salt .= "0" x 116;

    $salt_len += 116;
  }

  $salt = substr ($salt, 0, $salt_len % 2 ? $salt_len - 1 : $salt_len);

  my $salt_bin = pack ("H*", $salt);

  my $digest = hmac_hex ($salt_bin, $word, \&md5, 64);

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
