#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Digest::SHA qw (sha1);
use Crypt::CBC;
use Encode;

sub module_constraints { [[0, 256], [128, 128], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word  = shift;
  my $salt  = shift;
  my $iter  = shift // 10000;
  my $ct    = shift;

  my $pbkdf2 = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA1'),
    iterations => $iter,
    output_len => 48
  );

  my $salt_bin = pack ("H*", $salt);

  my $word_utf16le = encode ("UTF-16LE", $word);

  my $pbkdf2key = $pbkdf2->PBKDF2 ($salt_bin, $word_utf16le);

  my $key = substr ($pbkdf2key,  0, 32);
  my $iv  = substr ($pbkdf2key, 32, 16);

  my $pt;

  if (defined $ct)
  {
    my $aes_cbc = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      iv          => $iv,
      key         => $key,
      keysize     => 32,
      literal_key => 1,
      header      => "none",
      padding     => "none"
    });

    my $ct_bin = pack ("H*", $ct);

    $pt = $aes_cbc->decrypt ($ct_bin);

    if (substr ($pt, 4, 12) ne "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c")
    {
      $pt = "\xff" x 16;
    }
  }
  else
  {
    $pt = "\x30\x30\x30\x30\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
  }

  my $aes_cbc = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv,
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $ct_bin = $aes_cbc->encrypt ($pt);

  my $hash = sprintf ('$vbk$*%s*%d*%s', unpack ("H*", $salt_bin), $iter, unpack ("H*", $ct_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 5) eq '$vbk$';

  my ($signature, $salt, $iter, $ct) = split '\*', $hash;

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $iter;
  return unless defined $ct;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $iter, $ct);

  return ($new_hash, $word);
}

1;
