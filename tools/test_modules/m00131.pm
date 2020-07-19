#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1 qw (sha1_hex);
use Encode;

sub module_constraints { [[0, 256], [8, 8], [0, 27], [8, 8], [8, 27]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $digest = sha1_hex (encode ("UTF-16LE", uc ($word)) . $salt_bin);

  my $hash = sprintf ("0x0100%s%s%s", $salt, "0" x 40, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($digest, $word) = split (':', $line);

  my ($prefix, $hash) = split ('-', $digest);

  my $salt = substr ($prefix, 6, 8);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
