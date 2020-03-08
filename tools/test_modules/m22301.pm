#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256_hex);

sub module_constraints { [[0, 256], [32, 32], [0, 55], [32, 32], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $digest = sha256_hex ($salt_bin . $word . $salt_bin);

  my $hash = sprintf ("\$telegram\$0*%s*%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  my @data = split ('\*', $hash);

  return unless (scalar (@data) == 3);

  return unless (substr ($data[0], 0, 10) eq '$telegram$');

  my $version = substr ($data[0], 10);

  return unless ($version eq "0");

  my $digest = $data[1];
  my $salt   = $data[2];

  return unless (length ($digest) eq 64);
  return unless (length ($salt)   eq 32); # hex length

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
