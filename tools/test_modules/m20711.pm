#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256_hex);

sub module_constraints { [[0, 256], [16, 16], [0, 55], [16, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $digest = sha256_hex (sha256_hex ($word) . $salt);

  my $hash = sprintf ("\$SHA\$%s\$%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  return unless defined $digest;
  return unless defined $word;

  my (undef, $signature, $salt, $hash) = split ('\$', $digest);

  return unless ($signature eq 'SHA');
  return unless length ($salt) == 16;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
