#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1_hex);

sub module_constraints { [[0, 235], [20, 20], [0, 35], [20, 20], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $begin = "--" . $salt . "--";
  my $end   = "--" . $word . "----";

  my $digest = sha1_hex ($begin . $end);

  for (my $round = 1; $round < 10; $round++)
  {
    $digest = sha1_hex ($begin . $digest . $end);
  }

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
