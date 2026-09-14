#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::RC4;
use Digest::MD5 qw (md5);

# Mode 9710 is the first collider of mode 9700. The candidate is not the document
# password: it is the 5 byte, 40 bit RC4 key that mode 9700 derives from password
# and salt, which is why the kernel rejects every length but 5 and why the module
# hexifies the plain. The key is used as it comes, so this module never touches
# UTF-16 and never mixes the salt into the key. The salt is still part of the hash
# line, because the parser of mode 9710 is the parser of mode 9700, but it takes no
# part in the computation. Mode 9720, the second collider, turns the recovered key
# back into a password.

sub module_constraints { [[-1, -1], [-1, -1], [5, 5], [32, 32], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;

  # the candidate is the RC4 key itself, so every other length is out of reach

  return unless defined $word;
  return unless (length $word == 5);

  if (! defined $salt || length ($salt) == 0)
  {
    $salt = random_hex_string (32);
  }

  my $version;

  if (defined $param2)
  {
    $version = $param2;
  }
  else
  {
    $version = (unpack ("L", $word) & 1) ? 0 : 1;
  }

  my $rc4_key = md5 ($word . "\x00\x00\x00\x00");

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

  # Office Old $0 $1, collider #1

  # the candidate of this mode is a binary RC4 key, and a colon is a byte like any other, so
  # the line is cut once: everything behind the first colon is the password

  my ($hash_in, $word) = split (":", $line, 2);

  return unless defined $hash_in;
  return unless defined $word;

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

  # The plain of this mode is always hexified, and for a collider mode hashcat writes it
  # without the $HEX[] wrapper: outfile_write() forces the outfile format to 5, hash plus
  # hexplain, for every OPTS_TYPE_PT_ALWAYS_HEXIFY mode, and potfile_write() unhexifies the
  # $HEX[] form before it calls it. So a real crack line carries the 5 byte key as 10 hex
  # characters, and that is the form to decode first. A $HEX[] wrapped plain and a raw binary
  # one are accepted as well, for a pair that came from somewhere else.
  #
  # The key is packed for the computation and returned in the form it came in, the way
  # m00000.pm does it, because test.pl compares the returned pair against the line it read.

  my $word_packed = pack_if_HEX_notation ($word);

  if ($word_packed =~ m/^[0-9a-fA-F]{10}$/)
  {
    $word_packed = pack ("H*", $word_packed);
  }

  return unless (length $word_packed == 5);

  my $new_hash = module_generate_hash ($word_packed, $salt, $param, $param2);

  return ($new_hash, $word);
}

1;
