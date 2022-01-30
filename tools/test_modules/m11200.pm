#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1);

sub module_constraints { [[0, 256], [40, 40], [0, 55], [40, 40], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $sha1_pass   = sha1 ($word);
  my $double_sha1 = sha1 ($sha1_pass);

  my $xor_part1 = $sha1_pass;
  my $xor_part2 = sha1 (pack ("H*", $salt) . $double_sha1);

  my $digest = "";

  for (my $i = 0; $i < 20; $i++)
  {
    my $first_byte  = substr ($xor_part1, $i, 1);
    my $second_byte = substr ($xor_part2, $i, 1);

    my $xor_result = $first_byte ^ $second_byte;

    $digest .= unpack ("H*", $xor_result);
  }

  my $hash = sprintf ("\$mysqlna\$%s*%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split (/:/, $line);

  return unless defined $hash_in;
  return unless defined $word;

  my (undef, $signature, $digest) = split ('\$', $hash_in);

  my ($salt, $hash) = split ('\*', $digest);

  return unless ($signature eq 'mysqlna');
  return unless defined $salt;
  return unless defined $hash;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
