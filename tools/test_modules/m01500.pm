#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift // random_numeric_string (2);

  return if length $word > 8;

  my $hash = crypt ($word, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $salt = substr ($hash, 0, 2);

  my $new_hash = module_generate_hash ($word, $salt);

  return unless defined $new_hash;

  return unless $new_hash eq $hash;

  return $new_hash;
}

1;
