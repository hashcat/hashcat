#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [8, 8], [0, 55], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $user = shift // "postgres";

  my $digest = md5_hex (md5_hex ($word . $user) . pack ("H*", $salt));

  my $hash = sprintf ("\$postgres\$%s*%s*%s", $user, $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split (/:/, $line);

  return unless defined $hash_in;
  return unless defined $word;

  my (undef, $signature, $digest) = split ('\$', $hash_in);

  return unless ($signature eq 'postgres');

  my ($user, $salt, $hash) = split ('\*', $digest);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $user);

  return ($new_hash, $word);
}

1;
