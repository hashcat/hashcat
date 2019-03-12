#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::CRC  qw (crc32);
use Digest::SHA  qw (sha256);
use MIME::Base64 qw (encode_base64 decode_base64);

sub module_constraints { [[0, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iter = shift // 10000;

  # salt to UUID conversion

  my $UUID = unpack ("H*", substr ($salt,  0, 4)) . '-' .
             unpack ("H*", substr ($salt,  4, 2)) . '-' .
             unpack ("H*", substr ($salt,  6, 2)) . '-' .
             unpack ("H*", substr ($salt,  8, 2)) . '-' .
             unpack ("H*", substr ($salt, 10, 6));

  my $digest = sha256 ($UUID . $word);

  for (my $i = 0; $i < $iter - 1; $i++)
  {
    $digest = sha256 ($digest);
  }

  my $data = "bs:" . $digest . $salt . pack ("L<", $iter);

  # add the crc32 checksum at the end (4 bytes)

  $data .= pack ("L<", crc32 ($data));

  my $base64_data = encode_base64 ($data, '');

  return $base64_data;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  return unless length ($hash) == 80;

  my $bin_string = decode_base64 ($hash);

  return unless substr ($bin_string, 0, 3) eq "bs:";

  # crc32 (data corruption) check:

  return unless pack ("L<", crc32 (substr ($bin_string, 0, 55))) eq substr ($bin_string, 55, 4);

  my $digest   = substr ($bin_string,  3, 32);
  my $salt     = substr ($bin_string, 35, 16);
  my $iter_str = substr ($bin_string, 51,  4);

  my $iter = unpack ("L<", $iter_str);

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter);

  return ($new_hash, $word);
}

1;
