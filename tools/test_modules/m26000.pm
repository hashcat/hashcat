#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::DES;
use Crypt::DES_EDE3;
use Digest::SHA qw (sha1);
use Digest::HMAC qw (hmac);

sub module_constraints { [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word        = shift;
  my $global_salt = shift;
  my $entry_salt  = shift // random_hex_string (40);
  my $ct          = shift;

  my $global_salt_bin = pack ("H*", $global_salt);
  my $entry_salt_bin  = pack ("H*", $entry_salt);

  my $hp = sha1 ($global_salt_bin . $word);

  my $pes = substr ($entry_salt_bin . ("\x00" x 20), 0, 20);

  my $chp = sha1 ($hp . $entry_salt_bin);

  my $k1 = hmac ($pes . $entry_salt_bin, $chp, \&sha1, 64);

  my $tk = hmac ($pes, $chp, \&sha1, 64);

  my $k2 = hmac ($tk . $entry_salt_bin, $chp, \&sha1, 64);

  my $k = $k1 . $k2;

  my $key = substr ($k,  0, 24);
  my $iv  = substr ($k, 32,  8);

  my $pt;

  if (defined $ct)
  {
    my $ct_bin = pack ("H*", $ct);

    my $ede3 = Crypt::DES_EDE3->new ($key);

    my $ct1_bin = substr ($ct_bin, 0, 8);
    my $ct2_bin = substr ($ct_bin, 8, 8);

    my $pt1 = $ede3->decrypt ($ct1_bin);

    $pt1 = exclusive_or ($pt1, $iv);

    my $pt2 = $ede3->decrypt ($ct2_bin);

    $pt2 = exclusive_or ($pt2, $ct1_bin);

    $pt = $pt1 . $pt2;

    if ($pt ne "password-check\x02\x02")
    {
      $pt = "\xff" x 16;
    }
  }
  else
  {
    $pt = "password-check\x02\x02";
  }

  my $ede3 = Crypt::DES_EDE3->new ($key);

  my $pt1 = substr ($pt, 0, 8);
  my $pt2 = substr ($pt, 8, 8);

  $pt1 = exclusive_or ($pt1, $iv);

  my $ct1_bin = $ede3->encrypt ($pt1);

  $pt2 = exclusive_or ($pt2, $ct1_bin);

  my $ct2_bin = $ede3->encrypt ($pt2);

  my $ct_bin = $ct1_bin . $ct2_bin;

  my $hash = sprintf ('$mozilla$*3DES*%s*%s*%s', unpack ("H*", $global_salt_bin), unpack ("H*", $entry_salt_bin), unpack ("H*", $ct_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 9) eq '$mozilla$';

  my ($signature, $type, $global_salt, $entry_salt, $ct) = split '\*', $hash;

  return unless defined $signature;
  return unless defined $type;
  return unless defined $global_salt;
  return unless defined $entry_salt;
  return unless defined $ct;

  return unless $type eq '3DES';

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $global_salt, $entry_salt, $ct);

  return ($new_hash, $word);
}

sub exclusive_or
{
  my $in1 = shift;
  my $in2 = shift;

  my $out = "";

  for (my $i = 0; $i < length ($in1); $i++) # $i < $len
  {
    $out .= chr (ord (substr ($in1, $i, 1)) ^ ord (substr ($in2, $i, 1)));
  }

  return $out;
}

1;
