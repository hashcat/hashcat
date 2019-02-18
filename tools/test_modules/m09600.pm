#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::SHA qw (sha512);
use Encode;

sub module_constraints { [[0, 19], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 100000;
  my $param = shift;

  my $salt_bin = pack ("H*", $salt);

  my $tmp = sha512 ($salt_bin . encode ("UTF-16LE", $word));

  for (my $i = 0; $i < $iter; $i++)
  {
    my $num32 = pack ("L", $i);

    $tmp = sha512 ($num32 . $tmp);
  }

  my $encryptedVerifierHashInputBlockKey = "\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79";
  my $encryptedVerifierHashValueBlockKey = "\xd7\xaa\x0f\x6d\x30\x61\x34\x4e";

  my $final1 = sha512 ($tmp . $encryptedVerifierHashInputBlockKey);
  my $final2 = sha512 ($tmp . $encryptedVerifierHashValueBlockKey);

  my $key1 = substr ($final1, 0, 32);
  my $key2 = substr ($final2, 0, 32);

  my $cipher1 = Crypt::CBC->new ({
    key         => $key1,
    cipher      => "Crypt::Rijndael",
    iv          => $salt_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "null",
  });

  my $cipher2 = Crypt::CBC->new ({
    key         => $key2,
    cipher      => "Crypt::Rijndael",
    iv          => $salt_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "null",
  });

  my $encdata;

  if (defined $param)
  {
    $encdata = $cipher1->decrypt (pack ("H*", $param));
  }
  else
  {
    $encdata = "A" x 16; ## can be anything
  }

  my $data1_buf = $encdata;
  my $data2_buf = sha512 (substr ($data1_buf, 0, 16));

  my $encrypted1 = unpack ("H*", $cipher1->encrypt ($data1_buf));
  my $encrypted2 = unpack ("H*", $cipher2->encrypt ($data2_buf));

  $encrypted2 = substr ($encrypted2, 0, 64);

  my $hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2013, $iter, 256, 16, $salt, $encrypted1, $encrypted2);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office 2013
  my ($hash_in, $word) = split ":", $line;

  next unless defined $hash_in;
  next unless defined $word;

  my @data = split /\*/, $hash_in;

  next unless scalar @data == 8;

  next unless (shift @data eq '$office$');
  next unless (shift @data eq '2013');

  my $iter = shift @data;

  next unless (shift @data eq '256');
  next unless (shift @data eq '16');

  next unless (length $data[0] == 32);
  next unless (length $data[1] == 32);
  next unless (length $data[2] == 64);

  my $salt  = shift @data;
  my $param = shift @data;

  return unless defined $salt;
  return unless defined $iter;
  return unless defined $word;
  return unless defined $param;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter, $param);

  return ($new_hash, $word);
}

1;
