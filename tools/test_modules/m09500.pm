#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::CBC;
use Digest::SHA qw (sha1);
use Encode;

sub module_constraints { [[0, 19], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 100000;
  my $param = shift;

  my $salt_bin = pack ("H*", $salt);

  my $tmp = sha1 ($salt_bin . encode ("UTF-16LE", $word));

  for (my $i = 0; $i < $iter; $i++)
  {
    my $num32 = pack ("L", $i);

    $tmp = sha1 ($num32 . $tmp);
  }

  my $encryptedVerifierHashInputBlockKey = "\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79";
  my $encryptedVerifierHashValueBlockKey = "\xd7\xaa\x0f\x6d\x30\x61\x34\x4e";

  my $final1 = sha1 ($tmp . $encryptedVerifierHashInputBlockKey);
  my $final2 = sha1 ($tmp . $encryptedVerifierHashValueBlockKey);

  my $key1 = substr ($final1, 0, 16);
  my $key2 = substr ($final2, 0, 16);

  my $cipher1 = Crypt::CBC->new ({
    key         => $key1,
    cipher      => "Crypt::Rijndael",
    iv          => $salt_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 16,
    padding     => "none",
  });

  my $cipher2 = Crypt::CBC->new ({
    key         => $key2,
    cipher      => "Crypt::Rijndael",
    iv          => $salt_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 16,
    padding     => "none",
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
  my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

  my $encrypted1 = unpack ("H*", $cipher1->encrypt ($data1_buf));
  my $encrypted2 = unpack ("H*", $cipher2->encrypt ($data2_buf));

  $encrypted2 = substr ($encrypted2, 0, 64);

  my $hash = sprintf ("\$office\$*%d*%d*%d*%d*%s*%s*%s", 2010, $iter, 128, 16, $salt, $encrypted1, $encrypted2);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office 2010
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  return unless scalar @data == 8;

  return unless (shift @data eq '$office$');
  return unless (shift @data eq '2010');

  my $iter = shift @data;

  return unless (shift @data eq '128');
  return unless (shift @data eq '16');

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 64);

  my $salt  = shift @data;
  #my $iter  = shift @data;
  my $param = shift @data;

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $iter, $param);

  return ($new_hash, $word);
}

1;
