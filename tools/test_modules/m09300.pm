#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::ScryptKDF qw (scrypt_b64);

sub module_constraints { [[0, 256], [14, 14], [-1, -1], [-1, -1], [-1, -1]] }

my $CISCO_BASE64_MAPPING =
{
  'A', '.', 'B', '/', 'C', '0', 'D', '1', 'E', '2', 'F', '3', 'G', '4', 'H',
  '5', 'I', '6', 'J', '7', 'K', '8', 'L', '9', 'M', 'A', 'N', 'B', 'O', 'C',
  'P', 'D', 'Q', 'E', 'R', 'F', 'S', 'G', 'T', 'H', 'U', 'I', 'V', 'J', 'W',
  'K', 'X', 'L', 'Y', 'M', 'Z', 'N', 'a', 'O', 'b', 'P', 'c', 'Q', 'd', 'R',
  'e', 'S', 'f', 'T', 'g', 'U', 'h', 'V', 'i', 'W', 'j', 'X', 'k', 'Y', 'l',
  'Z', 'm', 'a', 'n', 'b', 'o', 'c', 'p', 'd', 'q', 'e', 'r', 'f', 's', 'g',
  't', 'h', 'u', 'i', 'v', 'j', 'w', 'k', 'x', 'l', 'y', 'm', 'z', 'n', '0',
  'o', '1', 'p', '2', 'q', '3', 'r', '4', 's', '5', 't', '6', 'u', '7', 'v',
  '8', 'w', '9', 'x', '+', 'y', '/', 'z'
};

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $N = 16384;
  my $r = 1;
  my $p = 1;

  my $hash_buf = scrypt_b64 ($word, $salt, $N, $r, $p, 32);

  my $tmp_hash = "";

  for (my $i = 0; $i < 43; $i++)
  {
    $tmp_hash .= $CISCO_BASE64_MAPPING->{substr ($hash_buf, $i, 1)};
  }

  my $hash = sprintf ('$9$%s$%s', $salt, $tmp_hash);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Cisco $9$ - scrypt
  return unless (substr ($line, 0, 3) eq '$9$');

  # get hash
  my $index1 = index ($line, "\$", 3);

  return if $index1 != 17;

  my $index2 = index ($line, "\$", $index1 + 1);

  # salt
  my $salt = substr ($line, 3,  $index1 - 3);

  $index1 = index ($line, ":", $index1 + 1);

  return if $index1 < 1;

  # digest

  my $word = substr ($line, $index1 + 1);

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;

