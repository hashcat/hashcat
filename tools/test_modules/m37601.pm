#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::MD5 qw (md5_hex);

sub module_constraints { [[0, 256], [10, 128], [0, 55], [0, 55], [0, 55]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  if (! defined $salt)
  {
    my $pid  = int (rand (9999)) + 1;
    my $time = int (rand (9999999999)) + 1000000000;
    my $host = "RESPONDER-" . random_hex_string (6);

    $salt = sprintf ("<%d.%d\@%s>", $pid, $time, $host);
  }

  my $digest = md5_hex ($salt . $word);

  my $hash = sprintf ("\$apop\$%s\$%s", $salt, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless length ($word) gt 0;
  return unless substr ($hash, 0, 6) eq '$apop$';

  my (undef, $signature, $salt, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $digest;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
