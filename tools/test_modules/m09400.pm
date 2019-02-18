#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Digest::SHA qw (sha1);
use Encode;

sub module_constraints { [[0, 19], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;

  my $iter = 50000;

  my $aes_key_size = 128; # or 256

  if (defined ($param2))
  {
    $aes_key_size = $param2;
  }

  my $salt_bin = pack ("H*", $salt);

  my $tmp = sha1 ($salt_bin . encode ("UTF-16LE", $word));

  for (my $i = 0; $i < $iter; $i++)
  {
    my $num32 = pack ("L", $i);

    $tmp = sha1 ($num32 . $tmp);
  }

  my $zero32 = pack ("L", 0x00);

  my $derivation_array1 = pack ("C", 0x36) x 64;
  my $derivation_array2 = pack ("C", 0x5C) x 64;

  $tmp = sha1 ($tmp . $zero32);

  my $tmp2 = sha1 ($derivation_array1 ^ $tmp);
  my $tmp3 = sha1 ($derivation_array2 ^ $tmp);

  my $key = substr ($tmp2 . $tmp3, 0, $aes_key_size / 8);

  my $m = Crypt::Mode::ECB->new ('AES', 0);

  my $encdata;

  if (defined $param)
  {
    $encdata = $m->decrypt (pack ("H*", $param), $key);
  }
  else
  {
    $encdata = "A" x 16; ## can be anything
  }

  my $data1_buf = $encdata;
  my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

  $data1_buf = substr ($data1_buf . ("\x00" x 16), 0, 16);
  $data2_buf = substr ($data2_buf . ("\x00" x 16), 0, 32);

  my $encrypted1 = unpack ("H*", $m->encrypt ($data1_buf, $key));
  my $encrypted2 = unpack ("H*", $m->encrypt ($data2_buf, $key));

  $encrypted1 = substr ($encrypted1, 0, 32);
  $encrypted2 = substr ($encrypted2, 0, 40);

  my $hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2007, 20, $aes_key_size, 16, $salt, $encrypted1, $encrypted2);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office 2007
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data == 8;

  return unless (shift @data eq '$office$');
  return unless (shift @data eq '2007');
  return unless (shift @data eq '20');

  my $aes_key_size = shift @data;

  return unless (($aes_key_size eq '128') || ($aes_key_size eq '256'));
  return unless (shift @data eq '16');

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 40);

  my $salt   = shift @data;
  my $param  = shift @data;
  my $param2 = $aes_key_size;

  return unless defined $salt;
  return unless defined $param;
  return unless defined $param2;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
