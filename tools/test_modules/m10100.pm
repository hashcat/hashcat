#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SipHash qw (siphash);

sub module_constraints { [[-1, -1], [-1, -1], [0, 55], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $seed = pack ("H*", $salt);

  my ($hi, $lo) = siphash ($word, $seed);

  my $hi_s = sprintf ("%08x", $hi);
  my $lo_s = sprintf ("%08x", $lo);

  $hi_s =~ s/^(..)(..)(..)(..)$/$4$3$2$1/;
  $lo_s =~ s/^(..)(..)(..)(..)$/$4$3$2$1/;

  my $hash = sprintf ("%s%s:2:4:%s", $hi_s, $lo_s, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, undef, undef, $salt, $word) = split ":", $line;

  return unless (length $hash == 16);
  return unless (length $salt == 32);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
