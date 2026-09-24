#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1);

# we need to restrict the pure password length for the test module to 63 bytes,
# because we can't have any string (including the pass) of over 63 bytes without "."

# DNSSEC NSEC3. The hashed owner name is iterated SHA1 over the DNS wire-format name (the lowercased
# password joined to the domain) followed by the salt, printed in base32hex. This is computed here
# directly rather than through Net::DNS, both to drop the Net::DNS::SEC dependency and because
# Net::DNS punycodes a non ASCII label (xn--...), which hashcat does not do: hashcat hashes the raw
# label bytes, so the raw wire encoding is what matches it.

sub module_constraints { [[1, 63], [1, 63], [1, 32], [1, 24], [1, 44]] }

sub nsec3_name2wire
{
  my $name = shift;

  my $wire = "";

  for my $label (split (/\./, $name, -1))
  {
    $wire .= chr (length ($label)) . $label;
  }

  return $wire . "\x00";
}

sub nsec3_base32hex
{
  my $data = shift;

  my @alpha = split (//, "0123456789abcdefghijklmnopqrstuv");

  my $bits = unpack ("B*", $data);

  my $out = "";

  for (my $i = 0; $i < length ($bits); $i += 5)
  {
    $out .= $alpha[oct ("0b" . substr ($bits, $i, 5))];
  }

  return $out;
}

sub nsec3_name2hash
{
  my ($name, $iter, $salt_hex) = @_;

  my $salt = pack ("H*", $salt_hex);

  my $digest = sha1 (nsec3_name2wire ($name) . $salt);

  for (1 .. $iter)
  {
    $digest = sha1 ($digest . $salt);
  }

  return nsec3_base32hex ($digest);
}

sub get_random_dnssec_salt
{
  my $domain = shift;

  my $salt_buf = "";

  $salt_buf .= ".";

  $salt_buf .= $domain;

  $salt_buf .= ":";

  $salt_buf .= random_numeric_string (8);

  return $salt_buf;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1;

  my $combined_salt = get_random_dnssec_salt ($salt);

  my ($domain, $salt_hex) = split (":", $combined_salt);

  my $name = lc ($word . $domain);

  my $hash_buf = nsec3_name2hash ($name, $iter, $salt_hex);

  my $hash = sprintf ("%s:%s:%s:%d", $hash_buf, $domain, $salt_hex, $iter);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my @datas = split (":", $line);

  return if scalar @datas != 5;

  my ($hash, $domain, $salt, $iter, $word) = @datas;

  # get_random_dnssec_salt () re-adds the leading '.', so strip it here first. Without this the
  # regenerated name gets two dots and verify never reproduces its own generate_hash.
  $domain =~ s/^\.//;

  $salt = $domain . ":" . $salt;

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
