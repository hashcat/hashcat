#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5);

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $digest1 = md5 ($word);

  my $digest1_sub = substr ($digest1, 0, 5);

  my $digest2 = md5 ($digest1_sub);

  my $digest2_sub = substr ($digest2, 0, 5);

  my $hash = sprintf ("%s", unpack ("H*", $digest2_sub));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;
