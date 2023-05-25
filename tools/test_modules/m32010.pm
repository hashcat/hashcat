#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA1;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $sha1 = Digest::SHA1->new;

  $sha1->add ($word);

  for (my $i = 1; $i < 100000; $i++)
  {
    my $tmp = $sha1->digest;

    $sha1->reset;

    $sha1->add ($tmp);
  }

  my $digest = $sha1->digest;

  my $hash = sprintf ('$sspr$1$100000$NONE$%s', unpack ("H*", $digest));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 20) eq '$sspr$1$100000$NONE$';

  my (undef, $signature, $version, $iter, $salt) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $iter;
  return unless defined $salt;

  return unless $version == 1;
  return unless $iter == 100000;
  return unless $salt eq "NONE";

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
