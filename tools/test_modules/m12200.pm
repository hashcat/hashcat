#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word         = shift;
  my $salt         = shift;
  my $default_salt = shift // 0;

  my $iterations = 65536;

  if ($default_salt == 1)
  {
    $salt = "0011223344556677";
  }

  my $digest = sha512 (pack ("H*", $salt) . $word);

  for (my $i = 0; $i < $iterations; $i++)
  {
    $digest = sha512 ($digest);
  }

  $digest = unpack ("H*", $digest);
  $digest = substr ($digest, 0, 16);

  my $hash;

  if ($default_salt == 0)
  {
    $hash = sprintf ("\$ecryptfs\$0\$1\$%s\$%s", $salt, $digest);
  }
  else
  {
    $hash = sprintf ("\$ecryptfs\$0\$%s", $digest);
  }

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split (/:/, $line);

  return unless defined $hash_in;
  return unless defined $word;

  my $signature = substr ($hash_in, 0, 12);

  return unless ($signature eq '$ecryptfs$0$');

  my $digest = substr ($hash_in, 12);

  my $default_salt = 1;

  my ($param, $hash) = split ('\$', $digest);

  $default_salt = 0 if ($param eq '1');

  my $salt;

  if ($default_salt == 0)
  {
    ($salt, $hash) = split ('\$', $hash);
  }

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $default_salt);

  return ($new_hash, $word);
}

1;
