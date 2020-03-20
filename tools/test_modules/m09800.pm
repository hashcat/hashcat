#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::SHA qw (sha1);
use Encode;

sub module_constraints { [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;
  my $param3 = shift;

  my $salt_bin = pack ("H*", $salt);

  my $tmp = sha1 ($salt_bin. encode ("UTF-16LE", $word));

  my $version;

  if (defined $param2)
  {
    $version = $param2;
  }
  else
  {
    $version = (unpack ("L", $tmp) & 1) ? 3 : 4;
  }

  my $rc4_key = sha1 ($tmp . "\x00\x00\x00\x00");

  if ($version == 3)
  {
    $rc4_key = substr ($rc4_key, 0, 5) . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
  }

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
  my $data2_buf = sha1 (substr ($data1_buf, 0, 16));

  $m = Crypt::RC4->new (substr ($rc4_key, 0, 16));

  my $encrypted1 = $m->RC4 ($data1_buf);
  my $encrypted2 = $m->RC4 ($data2_buf);


  my $secblock = "";

  if ($version == 3)
  {
    my $key2 = substr (sha1 ($tmp . "\x01\x00\x00\x00"), 0, 5) . "\x00" x 11;

    my $rc4 = Crypt::RC4->new ($key2);

    if (defined $param3) # verify/decrypt:
    {
      if (length ($param3) > 0)
      {
        my $decrypted = $rc4->RC4 (pack ("H*", $param3));

        # count the number of NUL (\x00) bytes:

        my $num_nul_bytes = 0;

        for (my $i = 0; $i < 32; $i++)
        {
          $num_nul_bytes++ if (substr ($decrypted, $i, 1) eq "\x00");
        }

        if ($num_nul_bytes < 10)
        {
          $secblock = "*"; # incorrect/fake/empty result
        }
        else
        {
          $secblock = "*$param3";
        }
      }
    }
    else
    {
      if (random_number (0, 1) == 1) # the second block data is optional
      {
        my $num_zeros = random_number (10, 32); # at least 10 NUL bytes

        $secblock = "\x00" x $num_zeros;

        # fill the buffer with some random bytes (up to 32 bytes total):

        for (my $i = 0; $i < 32 - $num_zeros; $i++)
        {
          my $idx = random_number (0, $num_zeros + $i); # insert at random position

          my $c = random_bytes (1); # 0x00-0xff

          $secblock = substr ($secblock, 0, $idx) . $c . substr ($secblock, $idx);
        }

        $secblock = $rc4->RC4 ($secblock);

        $secblock = "*" . unpack ("H*", $secblock);
      }
    }
  }

  my $hash = sprintf ("\$oldoffice\$%d*%s*%s*%s%s", $version, $salt, unpack ("H*", $encrypted1), unpack ("H*", $encrypted2), $secblock);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office Old $3 $4
  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split /\*/, $hash_in;

  my $num_fields = scalar @data;

  return unless (($num_fields == 4) || ($num_fields == 5));

  my $signature = shift @data;

  return unless (($signature eq '$oldoffice$3') || ($signature eq '$oldoffice$4'));

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 40);

  my $salt  = shift @data;
  my $param = shift @data;
  my $param2 = substr ($signature, 11, 1);

  my $param3 = "";

  if ($num_fields == 5)
  {
    shift @data; # ignore the "digest"

    $param3 = shift @data;
  }

  return unless defined $salt;
  return unless defined $word;
  return unless defined $param;
  return unless defined $param2;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param, $param2, $param3);

  return ($new_hash, $word);
}

1;
