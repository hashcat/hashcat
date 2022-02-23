#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256);

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = sha256 ($salt . sha256 ($word));

  my $hash = sprintf ("%s:%s", unpack ("H*", $digest), $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $salt, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
