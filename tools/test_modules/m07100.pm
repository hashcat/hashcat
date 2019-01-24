#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;

sub module_constraints { [[0, 255], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $unused = shift;
  my $salt   = shift // random_hex_string (64);
  my $iter   = shift // 1024;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => $iter
  );

  my $hash_buf = unpack ("H*", $pbkdf2->PBKDF2 (pack ("H*", $salt), $word));

  my $tmp_hash = sprintf ("\$ml\$%i\$%s\$%0128s", $iter, $salt, $hash_buf);

  return $tmp_hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ":");

  return if $index1 < 1;

  my $hash = substr ($line, 0, $index1);
  my $word = substr ($line, $index1 + 1);

  my $index2 =  index ($hash, "\$", 5);

  return if $index2 < 1;

  my $index3 =  index ($hash, "\$", $index2 + 1);

  my $salt = substr ($hash, $index2 + 1, $index3 - $index2 - 1);

  my $iter = substr ($hash, 4, $index2 - 4);

  return if (int ($iter) < 1);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, undef, $salt, $iter);

  return ($new_hash, $word);
}

1;
