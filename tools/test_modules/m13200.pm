#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::ECB;
use Digest::SHA qw (sha1);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub get_random_axcrypt_salt
{
  my $mysalt = random_bytes (16);

  $mysalt = unpack ("H*", $mysalt);

  my $iteration = random_number (6, 99999);

  my $salt_buf = $iteration . '*' . $mysalt;

  return $salt_buf;
}

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $param = shift;

  if (length $salt == 0)
  {
    $salt = get_random_axcrypt_salt ();
  }

  my @salt_arr = split ('\*', $salt);

  my $iteration = $salt_arr[0];

  my $mysalt = $salt_arr[1];

  $mysalt = pack ("H*", $mysalt);

  my $iv = "a6a6a6a6a6a6a6a6";

  my $KEK = sha1 ($word);

  $KEK = substr ($KEK ^ $mysalt, 0, 16);

  my $aes = Crypt::Mode::ECB->new ('AES', 0);

  my $B;

  my $A;

  my @R = ();

  if (defined $param)
  {
    $param = pack ("H*", $param);

    $A = substr ($param,  0, 8);
    $B = 0x00 x 8;

    $R[1] = substr ($param,  8, 8);
    $R[2] = substr ($param, 16, 8);

    for (my $j = $iteration - 1; $j >= 0; $j--)
    {
      $A = substr ($A, 0, 8) ^ pack ("l", (2 * $j + 2));

      $B = $R[2];

      $A = $aes->decrypt (substr ($A . $B . "\x00" x 16, 0, 16), $KEK);

      $R[2] = substr ($A, 8, 16);

      $A = substr ($A, 0, 8) ^ pack ("l", (2 * $j + 1));

      $B = $R[1];

      $A = $aes->decrypt (substr ($A . $B . "\x00" x 16, 0, 16), $KEK);

      $R[1] = substr ($A, 8, 16);
    }

    # check if valid
    if (index ($A, "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6") != 0)
    {
      # fake wrong @R and $A values

      @R = ('', "\x00" x 8, "\x00" x 8);

      $A = "\x00" x 16;
    }
  }
  else
  {
    my $DEK = random_hex_string (32);

    @R = ('', substr (pack ("H*", $DEK), 0, 8), substr (pack ("H*", $DEK), 8, 16));

    $A = pack ("H*", $iv);
  }

  for (my $j = 0; $j < $iteration; $j++)
  {
    $B = $aes->encrypt (substr ($A . $R[1] . "\x00" x 16, 0, 16), $KEK);

    $A = substr ($B, 0, 8) ^ pack ("q", (2 * $j + 1));

    $R[1] = substr ($B, 8, 16);

    $B = $aes->encrypt (substr ($A . $R[2] . "\x00" x 16, 0, 16), $KEK);

    $A = substr ($B, 0, 8) ^ pack ("q", (2 * $j + 2));

    $R[2] = substr ($B, 8, 16);
  }

  my $wrapped_key = unpack ("H*", $A . substr ($R[1], 0 ,8) . substr ($R[2], 0 ,8));

  $mysalt = unpack ("H*", $mysalt);

  my $hash = sprintf ('$axcrypt$*1*%s*%s*%s', $iteration, $mysalt, $wrapped_key);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash_in, $word) = split ":", $line;

  return unless defined $hash_in;
  return unless defined $word;

  my @data = split ('\*', $hash_in);

  return unless scalar @data == 5;

  my $signature = shift @data;
  my $version   = shift @data;
  my $iteration = shift @data;
  my $mysalt    = shift @data;
  my $digest    = shift @data;

  return unless ($signature eq '$axcrypt$');
  return unless (length ($mysalt) == 32);
  return unless (length ($digest) == 48);

  my $salt  = $iteration . '*' . $mysalt;
  my $param = $digest;

  return unless defined $salt;
  return unless defined $param;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt, $param);

  return ($new_hash, $word);
}

1;
