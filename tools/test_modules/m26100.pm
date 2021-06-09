#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;
use Digest::SHA qw (sha1);

sub module_constraints { [[0, 256], [40, 40], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word        = shift;
  my $global_salt = shift;
  my $entry_salt  = shift // random_hex_string (64);
  my $iter        = shift // 10000;
  my $iv          = shift // random_hex_string (32);
  my $ct          = shift;

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => 32
  );

  my $global_salt_bin = pack ("H*", $global_salt);

  my $global_key = sha1 ($global_salt_bin . $word);

  my $entry_salt_bin = pack ("H*", $entry_salt);

  my $entry_key = $kdf->PBKDF2 ($entry_salt_bin, $global_key);

  my $iv_bin = pack ("H*", $iv);

  my $pt;

  if (defined $ct)
  {
    my $aes_cbc = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      iv          => $iv_bin,
      key         => $entry_key,
      keysize     => 32,
      literal_key => 1,
      header      => "none",
      padding     => "none"
    });

    my $ct_bin = pack ("H*", $ct);

    $pt = $aes_cbc->decrypt ($ct_bin);

    if ($pt ne "password-check\x02\x02")
    {
      $pt = "\xff" x 16;
    }
  }
  else
  {
    $pt = "password-check\x02\x02";
  }

  my $aes_cbc = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv_bin,
    key         => $entry_key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $ct_bin = $aes_cbc->encrypt ($pt);

  my $hash = sprintf ('$mozilla$*AES*%s*%s*%d*%s*%s', unpack ("H*", $global_salt_bin), unpack ("H*", $entry_salt_bin), $iter, unpack ("H*", $iv_bin), unpack ("H*", $ct_bin));

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

  my ($signature, $type, $global_salt, $entry_salt, $iter, $iv, $ct) = split '\*', $hash;

  return unless defined $signature;
  return unless defined $type;
  return unless defined $global_salt;
  return unless defined $entry_salt;
  return unless defined $iter;
  return unless defined $iv;
  return unless defined $ct;

  return unless $type eq 'AES';

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $global_salt, $entry_salt, $iter, $iv, $ct);

  return ($new_hash, $word);
}

1;
