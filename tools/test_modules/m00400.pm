#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

my $itoa64_1 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

use strict;
use warnings;

use Authen::Passphrase::PHPass;

sub module_constraints { [[0, 256], [8, 8], [0, 55], [8, 8], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift;

  my $cost = 11;

  if (length ($iter))
  {
    $cost = $iter;
  }

  my $ppr = Authen::Passphrase::PHPass->new
  (
    cost       => $cost,
    salt       => $salt,
    passphrase => $word,
  );

  my $hash_buf = $ppr->as_rfc2307;

  return substr ($hash_buf, 7);
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my $salt = substr ($hash, 4, 8);

  # iterations = 2 ^ cost (where cost == $iter)
  my $iter = index ($itoa64_1, substr ($hash, 3, 1));

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return (substr ($hash, 0, 3) . substr ($new_hash, 3), $word);
}

1;
