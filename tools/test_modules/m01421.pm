#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256_hex);

sub module_constraints { [[0, 256], [6, 6], [0, 55], [6, 6], [6, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = sha256_hex ($salt . $word);

  my $hash = sprintf ("%s%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;
  return unless length ($hash) == 70;

  my $salt = substr ($hash, 0, 6);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
