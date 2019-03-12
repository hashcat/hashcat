#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::HMAC qw (hmac_hex);
use Digest::SHA qw (sha1);

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;
  my $param3 = shift;
  my $param4 = shift;
  my $param5 = shift;
  my $param6 = shift;

  my $iterations = 1000;

  my $type = 0;

  if (defined $param)
  {
    $type = $param;
  }

  my $mode = 1 + int rand (3);

  if (defined $param2)
  {
    $mode = $param2;
  }

  my $magic = 0;

  if (defined $param3)
  {
    $magic = $param3;
  }

  if (defined $param4)
  {
    $salt = $param4;
  }

  $salt = substr ($salt, 0, 8 + ($mode * 8));

  my $compress_length = 0;

  if (defined $param5)
  {
    $compress_length = $param5;
  }

  my $data = "";

  if (defined $param6)
  {
    $data = $param6;
  }

  my $key_len = (8 * ($mode & 3) + 8) * 2;

  my $out_len = $key_len + 2;

  my $salt_bin = pack ("H*", $salt);

  my $hasher = Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1');

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher      => $hasher,
    iterations  => $iterations,
    output_len  => $out_len
  );

  my $key = $pbkdf2->PBKDF2_hex ($salt_bin, $word);

  my $verify_bytes = substr ($key, -4); $verify_bytes =~ s/^0+//; #lol

  $key = substr ($key, $key_len, $key_len);

  my $key_bin = pack ("H*", $key);

  my $auth = hmac_hex ($data, $key_bin, \&sha1, 64);

  my $hash = sprintf ('$zip2$*%u*%u*%u*%s*%s*%u*%s*%s*$/zip2$', $type, $mode, $magic, $salt, $verify_bytes, $compress_length, $data, substr ($auth, 0, 20));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split ('\*', $hash_in);

  return unless scalar @data == 10;

  my $tag_start     = shift @data;
  my $type          = shift @data;
  my $mode          = shift @data;
  my $magic         = shift @data;
  my $salt          = shift @data;
  my $verify_bytes  = shift @data;
  my $length        = shift @data;
  my $data          = shift @data;
  my $auth          = shift @data;
  my $tag_end       = shift @data;

  return unless ($tag_start eq '$zip2$');
  return unless ($tag_end   eq '$/zip2$');

  my $param  = $type;
  my $param2 = $mode;
  my $param3 = $magic;
  my $param4 = $salt;
  my $param5 = $length;
  my $param6 = $data;

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param, $param2, $param3, $param4, $param5, $param6);

  return ($new_hash, $word);
}

1;
