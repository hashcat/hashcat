#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $idx  = shift;

  my $digest = md5_hex ($word);

  my $digest_half = substr ($digest, (defined $idx) ? $idx : 0, 16);

  my $hash = sprintf ("%s", $digest_half);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash1 = module_generate_hash ($word_packed, undef,  0);
  my $new_hash2 = module_generate_hash ($word_packed, undef,  8);
  my $new_hash3 = module_generate_hash ($word_packed, undef, 16);

  return ($new_hash1, $word) if ($hash eq $new_hash1);
  return ($new_hash2, $word) if ($hash eq $new_hash2);
  return ($new_hash3, $word) if ($hash eq $new_hash3);

  return ("invalid", $word);
}

1;
