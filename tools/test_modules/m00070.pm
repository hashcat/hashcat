#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);
use Encode;

sub module_constraints { [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $digest = md5_hex (encode ("UTF-16LE", $word));

  my $hash = sprintf ("%s", $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word);

  return ($new_hash, $word);
}

1;
