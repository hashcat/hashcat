#!/usr/bin/env perl

##
## Author......: net-doge
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD4 qw (md4_hex);
use Encode;

sub module_constraints { [[0, 256], [0, 256], [0, 55], [0, 55], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;

  # Pass 1: NTLM(password) = MD4(UTF-16LE(password))
  my $inner = md4_hex (encode ("UTF-16LE", $word));

  # Pass 2: NTLM(hex_string) = MD4(UTF-16LE(lowercase_hex))
  my $digest = md4_hex (encode ("UTF-16LE", $inner));

  my $hash = sprintf ("%s", $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (/:/, $line, 2);

  return unless defined $hash;
  return unless defined $word;
  return unless length ($hash) == 32;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;
