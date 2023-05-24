#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA;

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $sha256 = Digest::SHA->new(256);

  $sha256->add ($salt . $word);

  for (my $i = 1; $i < 1000; $i++)
  {
    my $tmp = $sha256->digest;

    $sha256->reset;

    $sha256->add ($tmp);
  }

  my $digest = $sha256->digest;

  my $hash = sprintf ('$sspr$3$1000$%s$%s', $salt, unpack ("H*", $digest));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 13) eq '$sspr$3$1000$';

  my (undef, $signature, $version, $iter, $salt) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $iter;
  return unless defined $salt;

  return unless $version == 3;
  return unless $iter == 1000;
  return unless length $salt == 16;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
