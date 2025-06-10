#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;
use Encode qw(encode);

sub module_constraints { [[0, 256], [-1, -1], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $iter = shift;
  my $ct   = shift;

  $iter = 10000 unless defined ($iter) && $iter =~ /^\d+$/;

  my $hid = 0;

  my $iv = "\x00" x 16;

  my $key_len = 32;

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 256),
    iterations => $iter,
    output_len => $key_len,
    salt_len   => 0
  );

  my $word_utf16le = encode ("UTF-16LE", $word);

  my $key = $kdf->PBKDF2 ('', $word_utf16le);

  my $is_decrypt = defined ($ct);

  my $data_bin;

  if ($is_decrypt == 1)
  {
    $data_bin = pack ("H*", $ct);

    my $aes = Crypt::CBC->new ({
      cipher      => "Crypt::Rijndael",
      key         => $key,
      iv          => $iv,
      keysize     => $key_len,
      literal_key => 1,
      header      => "none",
      padding     => "standard",
    });

    my $pt_bin = $aes->decrypt ($data_bin);

    my $pt = unpack ("H*", $pt_bin);
    my $pt_tmp = substr ($pt, 0, 16);

    my $kp = "\x00\x00\x00\x00\x01\x00\x00\x00";
    my $kp_tmp = unpack ("H*", $kp);

    if ($pt_tmp eq $kp_tmp)
    {
      $data_bin = $pt_bin;
    }
  }
  else
  {
    $data_bin = pack ("H*", "000000000100000000000000600000006000000000000000200000004000");
  }

  my $aes = Crypt::CBC->new ({
    cipher      => "Crypt::Rijndael",
    key         => $key,
    iv          => $iv,
    keysize     => $key_len,
    literal_key => 1,
    header      => "none",
    padding     => "standard",
  });

  my $ct_bin = $aes->encrypt ($data_bin);

  my $hash = sprintf ('$MSONLINEACCOUNT$%d$%d$%s', $hid, $iter, unpack ("H*", $ct_bin));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 18) eq '$MSONLINEACCOUNT$0';

  my (undef, $signature, $hid, $iter, $ct) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $hid;
  return unless defined $iter;
  return unless defined $ct;

  return unless ($signature eq 'MSONLINEACCOUNT');
  return unless ($hid eq '0');

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $iter, $ct);

  return ($new_hash, $word);
}

1;
