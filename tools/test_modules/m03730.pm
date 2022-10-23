#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [0, 256], [0, 55], [0, 23], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt1 = shift;
  my $salt2 = shift || random_numeric_string (128);
  
  my $digest = md5_hex ($salt1 . uc(md5_hex ($salt2 . $word)));

  my $hash = sprintf ("%s:%s:%s", $digest, $salt1, $salt2);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt1, $salt2, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt1;
  return unless defined $salt2;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt1, $salt2);

  return ($new_hash, $word);
}

1;
