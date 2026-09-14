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
  my $salt   = shift // random_hex_string (32);
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

  # these 5 bytes are the digest of this collider mode, the 40 bit key mode 9710 recovers

  my $rc4key = $tmp;

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

  my $hash = sprintf ("\$oldoffice\$%d*%s*%s*%s:%s", $version, $salt, unpack ("H*", $encrypted1), unpack ("H*", $encrypted2), unpack ("H*", $rc4key));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office Old $0 $1, collider #2

  my ($hash_in, $rc4key, $word) = split (':', $line, 3);

  return unless defined $hash_in;
  return unless defined $rc4key;
  return unless defined $word;

  # The plain is packed for the computation but returned in the form it came in, the way
  # m00000.pm does it, because test.pl compares the returned pair against the line it read.
  # hashcat writes a plain that carries the separator, ends in whitespace or is not printable
  # as $HEX[...], and the packed form would no longer match that line.

  my $word_packed = pack_if_HEX_notation ($word);

  return unless (length $rc4key == 10);

  my @data = split /\*/, $hash_in;

  return unless scalar @data == 4;

  my $signature = shift @data;

  return unless (($signature eq '$oldoffice$0') || ($signature eq '$oldoffice$1'));

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 32);

  my $salt   = shift @data;
  my $param  = shift @data;
  my $param2 = substr ($signature, 11, 1);

  return unless defined $salt;
  return unless defined $param;
  return unless defined $param2;

  my $new_hash = module_generate_hash ($word_packed, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
