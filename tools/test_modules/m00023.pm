#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 247], [0, 247], [0, 47], [0, 47], [0, 47]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  # we need to reduce the maximum password and salt buffer size by 8 since we
  # add it here statically

  my $final = sprintf ("%s\nskyper\n%s", $salt, $word);

  my $digest = md5_hex ($final);

  my $hash = sprintf ("%s:%s", $digest, $salt);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
