#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift // random_numeric_string (random_count (15));

  my $hash = md5_hex ($salt . $word) . ":$salt";

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return unless defined $new_hash;

  return unless $new_hash eq "$hash:$salt";

  return $new_hash;
}

1;
