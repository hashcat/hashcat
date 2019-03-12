#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;

use Digest::SHA  qw (sha256);
use MIME::Base64 qw (encode_base64);

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

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

  my $digest = sha256 ($word);

  my $base64_buf = encode_base64 ($digest, "");

  my $hash = "";

  for (my $i = 0; $i < 43; $i++)
  {
    $hash .= $CISCO_BASE64_MAPPING->{substr ($base64_buf, $i, 1)};
  }

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
