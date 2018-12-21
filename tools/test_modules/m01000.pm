#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Encode;

sub module_generate_hash
{
  my $word = shift;

  return if length $word > 27;

  my $hash = md4_hex (encode ("UTF-16LE", $word));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split ":", $line;

  return unless defined $hash;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word);

  return unless defined $new_hash;

  return unless $new_hash eq $hash;

  return $new_hash;
}

1;
