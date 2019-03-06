#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt = shift;
  my $site_key = shift || random_numeric_string (40);

  my $digest = sha1_hex ($site_key . '--' . $salt . '--' . $word . '--'. $site_key);

  for (my $i = 0; $i < 9; $i++) {
    $digest = sha1_hex ($digest . '--' . $salt . '--' . $word . '--'. $site_key);
  }

  my $hash = sprintf ("%s:%s:%s", $digest, $salt, $site_key);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $salt, $site_key, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $salt;
  return unless defined $site_key;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $site_key);

  return ($new_hash, $word);
}

1;
