#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::MD5 qw (md5);
use Encode;

sub module_constraints { [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;

  my $salt_bin = pack ("H*", $salt);

  my $tmp = md5 (encode ("UTF-16LE", $word));

  $tmp = substr ($tmp, 0, 5);

  my $data;

  for (my $i = 0; $i < 16; $i++)
  {
    $data .= $tmp;
    $data .= $salt_bin;
  }

  $tmp = md5 ($data);

  $tmp = substr ($tmp, 0, 5);

  my $version;

  if (defined $param2)
  {
    $version = $param2;
  }
  else
  {
    $version = (unpack ("L", $tmp) & 1) ? 0 : 1;
  }

  my $rc4_key = md5 ($tmp . "\x00\x00\x00\x00");

  my $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

  my $encdata;

  if (defined $param)
  {
    $encdata = $m->RC4 (pack ("H*", $param));
  }
  else
  {
    $encdata = "A" x 16; ## can be anything
  }

  my $data1_buf = $encdata;
  my $data2_buf = md5 (substr ($data1_buf, 0, 16));

  $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

  my $encrypted1 = $m->RC4 ($data1_buf);
  my $encrypted2 = $m->RC4 ($data2_buf);

  my $hash = sprintf ("\$oldoffice\$%d*%s*%s*%s", $version, $salt, unpack ("H*", $encrypted1), unpack ("H*", $encrypted2));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office Old $1 $2
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data == 4;

  my $signature = shift @data;

  return unless (($signature eq '$oldoffice$0') || ($signature eq '$oldoffice$1'));

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 32);

  my $salt  = shift @data;
  my $param = shift @data;
  my $param2 = substr ($signature, 11, 1);

  return unless defined $salt;
  return unless defined $word;
  return unless defined $param;
  return unless defined $param2;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
