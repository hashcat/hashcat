#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 253], [8, 8], [0, 53], [8, 8], [8, 53]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $signature = "01";

  my $salt_bin = pack ("H*", $salt . $signature);

  my $digest = sha1_hex ($salt_bin . $word);

  my $hash = sprintf ("%s%s%s", $salt, $signature, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  my $salt = substr ($hash, 0, 8);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
