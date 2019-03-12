#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha256_hex);
use Encode;

sub module_constraints { [[-1, -1], [-1, -1], [0, 27], [16, 16], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $salt_bin = pack ("H*", $salt);

  my $word_utf = encode ("UTF-16BE", $word);

  my $hash_buf = sha256_hex ($word_utf . "\x00" x (510 - (length ($word) * 2)) . $salt_bin);

  my $hash = sprintf ("0xc007%s%s", $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Sybase ASE
  my $index = index ($line, ":");

  return if $index < 1;

  my $hash_in = substr ($line, 0, $index);

  my $word = substr ($line, $index + 1);

  my $salt = substr ($hash_in, 6, 16);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
