#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::OpenSSH::ChachaPoly;

sub module_constraints { [[32, 32], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word   = shift;
  my $salt   = shift;
  my $param  = shift;
  my $param2 = shift;
  my $param3 = shift;

  my $counter;
  my $offset;
  my $iv;

  if (defined $param)
  {
    $counter = $param;
    $offset  = $param2;
    $iv      = $param3;
  }
  else
  {
    $counter = "0400000000000003";
    $offset  = int (rand (63));
    $iv      = "0200000000000001";
  }

  my $plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0a2b4c6d8e";
  my $eight_byte_iv = pack ("H*", $iv);
  my $eight_byte_counter = pack ("H*", $counter);
  #my $pad_len = 32 - length ($word);
  #my $key = $word . "\0" x $pad_len;
  my $key = $word;

  my $cipher = Crypt::OpenSSH::ChachaPoly->new ($key);

  $cipher->ivsetup ($eight_byte_iv, $eight_byte_counter);

  my $enc = $cipher->encrypt ($plaintext);

  my $enc_offset = substr ($enc, $offset, 8);

  my $hash_buf = $enc_offset;

  my $hash = sprintf ("\$chacha20\$\*%s\*%d\*%s\*%s\*%s", $counter, $offset, $iv, unpack ("H*", substr ($plaintext, $offset, 8)), unpack ("H*", $enc_offset));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $index1 = index ($line, ':');

  return if ($index1 < 0);

  my $hash_in = substr ($line, 0, $index1);

  my $word = substr ($line, $index1 + 1);

  return if (length ($hash_in) < 11);

  return unless (substr ($hash_in, 0, 11) eq "\$chacha20\$\*");

  my @data = split ('\*', $hash_in);

  return unless (scalar (@data) == 6);

  my $param  = $data[1]; # counter
  my $param2 = $data[2]; # offset
  my $param3 = $data[3]; # iv

  return unless defined $param;
  return unless defined $param2;
  return unless defined $param3;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, undef, $param, $param2, $param3);

  return ($new_hash, $word);
}

1;
