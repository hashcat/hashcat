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

# Mode 9820 is the second collider of mode 9800, and the counterpart of mode 9810.
# The candidate is the document password again, but what the kernel compares is not
# the encrypted verifier: it is the 5 byte, 40 bit RC4 key that mode 9800 derives
# from password and salt, sha1 (sha1 (salt . utf16le (pass)) . 00000000) cut to five
# bytes, see digest[] in src/modules/module_09820.c. That key is what mode 9810
# recovers, and this mode turns it back into a password. The hash line is the hash
# line of mode 9800 with those five bytes appended as ten hex digits behind a colon,
# so the line itself already holds a colon and the password is the third field.
# Only the $3 variant of mode 9800 has a 40 bit key, so the version of a generated
# hash is always 3.

sub module_constraints { [[-1, -1], [-1, -1], [0, 15], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift; # the encrypted verifier of an existing hash
  my $param2 = shift; # the second block data of an existing hash

  if (! defined $salt || length ($salt) == 0)
  {
    $salt = random_hex_string (32);
  }

  my $salt_bin = pack ("H*", $salt);

  my $tmp = sha1 ($salt_bin . encode ("UTF-16LE", $word));

  # this mode is the collider of the $3 variant only, so the key is always a 40 bit one

  my $version = 3;

  my $key = sha1 ($tmp . "\x00\x00\x00\x00");

  # the digest of this mode is the RC4 key itself, the first five bytes of the key above

  my $rc4key = substr ($key, 0, 5);

  my $rc4_key = $rc4key . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

  my $m = Crypt::RC4->new ($rc4_key);

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

  $m = Crypt::RC4->new ($rc4_key);

  my $encrypted1 = $m->RC4 ($data1_buf);
  my $encrypted2 = $m->RC4 ($data2_buf);

  my $secblock = "";

  my $key2 = substr (sha1 ($tmp . "\x01\x00\x00\x00"), 0, 5) . "\x00" x 11;

  my $rc4 = Crypt::RC4->new ($key2);

  if (defined $param2) # verify/decrypt:
  {
    if (length ($param2) > 0)
    {
      my $decrypted = $rc4->RC4 (pack ("H*", $param2));

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
        $secblock = "*$param2";
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

  my $hash = sprintf ("\$oldoffice\$%d*%s*%s*%s%s:%s", $version, $salt, unpack ("H*", $encrypted1), unpack ("H*", $encrypted2), $secblock, unpack ("H*", $rc4key));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office Old $3, collider #2

  # the hash of this mode carries the RC4 key behind a colon of its own, so the line has
  # three fields and only the last one of them is the password

  my @fields = split (":", $line, 3);

  return unless (scalar @fields == 3);

  my $hash_in = shift @fields;
  my $rc4key  = shift @fields;
  my $word    = shift @fields;

  return unless defined $hash_in;
  return unless defined $rc4key;
  return unless defined $word;

  return unless (length $rc4key == 10);

  # The plain is packed for the computation but returned in the form it came in, because test.pl
  # compares the returned pair against the line it read, and hashcat writes a plain that carries the
  # separator, ends in whitespace or is not printable as $HEX[...].

  my $word_packed = pack_if_HEX_notation ($word);

  my @data = split /\*/, $hash_in;

  my $num_fields = scalar @data;

  return unless (($num_fields == 4) || ($num_fields == 5));

  my $signature = shift @data;

  return unless ($signature eq '$oldoffice$3');

  return unless (length $data[0] == 32);
  return unless (length $data[1] == 32);
  return unless (length $data[2] == 40);

  my $salt  = shift @data;
  my $param = shift @data;

  my $param2 = "";

  if ($num_fields == 5)
  {
    shift @data; # the encrypted verifier hash, which this mode does not use

    $param2 = shift @data;
  }

  return unless defined $salt;
  return unless defined $word;
  return unless defined $param;

  my $new_hash = module_generate_hash ($word_packed, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
