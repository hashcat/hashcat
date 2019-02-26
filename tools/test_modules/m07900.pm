#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha512);
use Authen::Passphrase::PHPass;

sub module_constraints { [[0, 256], [8, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $cost = shift // 14;

  my $phpass_it = 1 << $cost;

  my $hash_buf = sha512 ($salt . $word);

  for (my $i = 0; $i < $phpass_it; $i++)
  {
    $hash_buf = sha512 ($hash_buf . $word);
  }

  my $base64_buf = substr (Authen::Passphrase::PHPass::_en_base64 ($hash_buf), 0, 43);

  my $base64_digits = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $cost_str = substr ($base64_digits, $cost, 1);

  my $hash = sprintf ('$S$%s%s%s', $cost_str, $salt, $base64_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index = index ($line, ":");

  return if $index < 1;

  my $hash_in = substr ($line, 0, $index);

  my $word = substr ($line, $index + 1);

  my $salt = substr ($hash_in, 4, 8);

  # iterations = 2 ^ cost (where cost == $iter)

  my $itoa64_1 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  my $iter = index ($itoa64_1, substr ($hash_in, 3, 1));

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
