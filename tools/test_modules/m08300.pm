#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Net::DNS::RR::NSEC3;
use Net::DNS::SEC;

sub module_constraints { [[1, 256], [-1, -1], [1, 55], [-1, -1], [-1, -1]] }

sub get_random_dnssec_salt
{
  my $salt_buf = "";

  $salt_buf .= ".";

  $salt_buf .= random_lowercase_string (8);

  $salt_buf .= ".net";

  $salt_buf .= ":";

  $salt_buf .= random_numeric_string (8);

  return $salt_buf;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1;

  if (length $salt == 0)
  {
    $salt = get_random_dnssec_salt ();
  }

  my ($domain, $salt_hex) = split (":", $salt);

  my $hashalg = Net::DNS::SEC->digtype ("SHA1");

  my $name = lc ($word . $domain);

  my $hash_buf = Net::DNS::RR::NSEC3::name2hash ($hashalg, $name, $iter, $salt_hex);

  my $hash = sprintf ("%s:%s:%s:%d", $hash_buf, $domain, $salt_hex, $iter);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my @datas = split (":", $line);

  return if scalar @datas != 5;

  my ($hash, $domain, $salt, $iter, $word) = @datas;

  $salt = $domain . ":" . $salt;

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;

