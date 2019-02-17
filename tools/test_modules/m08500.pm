#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Convert::EBCDIC qw (ascii2ebcdic);
use Crypt::DES;

sub module_constraints { [[0, 8], [1, 8], [-1, -1], [-1, -1], [-1, -1]] }

sub racf_hash
{
  my ($username, $password) = @_;

  $username = substr ($username . " " x 8, 0, 8);
  $password = substr ($password . " " x 8, 0, 8);

  my $username_ebc = ascii2ebcdic ($username);
  my $password_ebc = ascii2ebcdic ($password);

  my @pw = split ("", $password_ebc);

  for (my $i = 0; $i < 8; $i++)
  {
    $pw[$i] = unpack ("C", $pw[$i]);
    $pw[$i] ^= 0x55;
    $pw[$i] <<= 1;
    $pw[$i] = pack ("C", $pw[$i] & 0xff);
  }

  my $key = join ("", @pw);

  my $cipher = new Crypt::DES $key;

  my $ciphertext = $cipher->encrypt ($username_ebc);

  my $ct = unpack ("H16", $ciphertext);

  return $ct;
}

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $hash_buf = racf_hash (uc $salt, $word);

  my $hash = sprintf ('$racf$*%s*%s', uc $salt, uc $hash_buf);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my @line_elements = split (":", $line);

  return if scalar @line_elements < 2;

  my $hash_in = shift @line_elements;

  my $word = join (":", @line_elements);

  # check signature

  my @hash_elements = split ('\*', $hash_in);

  return unless ($hash_elements[0] eq '$racf$');

  my $salt = $hash_elements[1];

  return unless defined $salt;
  return unless defined $word;

  $word = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word, $salt);

  return ($new_hash, $word);
}

1;
