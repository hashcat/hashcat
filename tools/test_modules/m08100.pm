#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 256], [8, 8], [0, 54], [8, 8], [8, 54]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $hash_buf = sha1_hex ($salt . $word . "\x00");

  my $hash = sprintf ("1%s%s", $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $salt = substr ($line, 1, 8);

  my $rest = substr ($line, 1 + 8);

  my $index2 = index ($rest, ":");

  return if $index2 < 1;

  my $word = substr ($rest, $index2 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
