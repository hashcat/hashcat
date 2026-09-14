#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::SHA qw (sha1);

# Mode 9810 is the first collider of mode 9800. The candidate is not the document
# password: it is the 5 byte, 40 bit RC4 key that mode 9800 derives from password
# and salt, which is why the kernel rejects every length but 5 and why the module
# hexifies the plain. The key is used as it comes, so this module never touches
# UTF-16 and never mixes the salt into the key. The salt is still part of the hash
# line, because the parser of mode 9810 is the parser of mode 9800, but it takes no
# part in the computation. Only the $3 variant of mode 9800 has a 40 bit key, so the
# version of a generated hash is always 3. Mode 9820, the second collider, turns the
# recovered key back into a password.

sub module_constraints { [[-1, -1], [-1, -1], [5, 5], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift; # the encrypted verifier of an existing hash
  my $param2 = shift; # the second block data of an existing hash

  # the candidate is the RC4 key itself, so every other length is out of reach

  return unless defined $word;
  return unless (length $word == 5);

  if (! defined $salt || length ($salt) == 0)
  {
    $salt = random_hex_string (32);
  }

  my $version = 3;

  # the kernel pads the 5 candidate bytes with 11 zero bytes, see key[] in
  # OpenCL/m09810_a4-optimized.cl, and drives RC4 with the 16 bytes of that

  my $rc4_key = $word . "\x00" x 11;

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

  # mode 9800 decrypts the optional second block data with a key of its own, derived
  # from the password with sha1. This mode never sees the password, so it cannot build
  # that key: the block is carried over untouched and is never generated.

  my $secblock = "";

  if ((defined $param2) && (length ($param2) > 0))
  {
    $secblock = "*$param2";
  }

  my $hash = sprintf ("\$oldoffice\$%d*%s*%s*%s%s", $version, $salt, unpack ("H*", $encrypted1), unpack ("H*", $encrypted2), $secblock);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  # Office Old $3, collider #1

  # the candidate of this mode is a binary RC4 key, and a colon is a byte like any other, so
  # the line is cut once: everything behind the first colon is the password

  my ($hash_in, $word) = split (":", $line, 2);

  return unless defined $hash_in;
  return unless defined $word;

  # The plain of this mode is hexified, never raw. OPTS_TYPE_PT_ALWAYS_HEXIFY forces the outfile
  # format to hash:hexplain, see the branch on it in src/outfile.c, so an outfile line and a
  # --show line carry the key as bare hex, and a potfile line carries the same key as $HEX[...].
  # Both are decoded here, and the plain is handed back in the form it came in, the way m00000.pm
  # does it, because test.pl compares the returned pair against the line it read. A raw 5 byte key
  # is 5 characters long and never matches the bare hex form, so a hand written line still works.

  my $word_packed = pack_if_HEX_notation ($word);

  if ($word_packed =~ m/^[0-9a-fA-F]{10}$/)
  {
    $word_packed = pack ("H*", $word_packed);
  }

  return unless (length $word_packed == 5);

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
    shift @data; # ignore the "digest"

    $param2 = shift @data;
  }

  return unless defined $salt;
  return unless defined $param;

  my $new_hash = module_generate_hash ($word_packed, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
