#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;

sub module_constraints { [[0, 256], [32, 32], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $type = shift // 1; #random_number (1, 3);
  my $iter = shift // random_number (10000, 20000);
  my $iv   = shift // random_hex_string (32);
  my $enc  = shift;

  my $kdf;

  if ($type == 1)
  {
    $kdf = Crypt::PBKDF2->new
    (
      hash_class => 'HMACSHA1',
      iterations => $iter,
      output_len => 32
    );
  }
  elsif ($type == 2)
  {
    $kdf = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
      iterations => $iter,
      output_len => 32
    );
  }
  elsif ($type == 3)
  {
    $kdf = Crypt::PBKDF2->new
    (
      hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
      iterations => $iter,
      output_len => 32
    );
  }

  my $salt_bin = pack ("H*", $salt);

  my $key = $kdf->PBKDF2 ($salt_bin, $word);

  my $iv_bin = pack ("H*", $iv);

  my $data;

  if (defined $enc)
  {
    my $aes_cbc = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      iv          => $iv_bin,
      key         => $key,
      keysize     => 32,
      literal_key => 1,
      header      => "none",
      padding     => "none"
    });

    my $enc_bin = pack ("H*", $enc);

    $data = $aes_cbc->decrypt ($enc_bin);

    if (substr ($data, 0, 12) ne "\x00" x 12)
    {
      $data = "\xff" x 16;
    }
  }
  else
  {
    $data = "\x00" x 16;
  }

  my $aes_cbc = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    iv          => $iv_bin,
    key         => $key,
    keysize     => 32,
    literal_key => 1,
    header      => "none",
    padding     => "none"
  });

  my $enc_bin = $aes_cbc->encrypt ($data);

  my $hash = sprintf ("SQLCIPHER*%d*%d*%s*%s*%s", $type, $iter, unpack ("H*", $salt_bin), unpack ("H*", $iv_bin), unpack ("H*", $enc_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 9) eq 'SQLCIPHER';

  my ($signature, $type, $iter, $salt, $iv, $data) = split '\*', $hash;

  return unless defined $signature;
  return unless defined $type;
  return unless defined $iter;
  return unless defined $salt;
  return unless defined $iv;
  return unless defined $data;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $type, $iter, $iv, $data);

  return ($new_hash, $word);
}

1;
