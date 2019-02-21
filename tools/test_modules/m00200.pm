#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Authen::Passphrase::MySQL323;

sub module_constraints { [[-1, -1], [-1, -1], [0, 31], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;

  my $ppr = Authen::Passphrase::MySQL323->new (passphrase => $word);

  my $digest = $ppr->hash_hex;

  my $hash = sprintf ("%s", $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed);

  return ($new_hash, $word);
}

1;
