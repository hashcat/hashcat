#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $param = shift;

  my $length = 32;

  if ($param)
  {
    $length = $param;
  }

  my $hash_buf = sha1_hex ($word);

  my $hash = sprintf ('$axcrypt_sha1$%s', substr ($hash_buf, 0, $length));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  next unless defined $hash_in;
  next unless defined $word;

  my @data = split ('\$', $hash_in);

  next unless scalar @data == 3;

  shift @data;

  my $signature = shift @data;
  my $digest    = shift @data;

  my $param = length ($digest);

  next unless ($signature eq 'axcrypt_sha1');
  next unless (($param == 32) || ($param == 40));

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, undef, $param);

  return ($new_hash, $word);
}

1;
