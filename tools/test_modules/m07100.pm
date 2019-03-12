#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 1024;

  if (length $salt == 0)
  {
    $salt = random_hex_string (64, 64);
  }

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter
  );

  my $hash_buf = unpack ("H*", $pbkdf2->PBKDF2 (pack ("H*", $salt), $word));

  my $hash = sprintf ("\$ml\$%i\$%s\$%0128s", $iter, $salt, $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  my $index2 = index ($hash_in, "\$", 5);

  return if $index2 < 1;

  my $index3 = index ($hash_in, "\$", $index2 + 1);

  my $salt = substr ($hash_in, $index2 + 1, $index3 - $index2 - 1);

  my $iter = substr ($hash_in, 4, $index2 - 4);

  return if (int ($iter) < 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter);

  return ($new_hash, $word);
}

1;
