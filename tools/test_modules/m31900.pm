#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::PBKDF2;
use Crypt::CBC;
use MIME::Base64 qw (decode_base64 encode_base64);

sub module_constraints { [[8, 256], [16, 16], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $iv   = shift // random_hex_string (32);
  my $ct   = shift;

  my $kdf = Crypt::PBKDF2->new
  (
    hasher     => Crypt::PBKDF2->hasher_from_algorithm ('HMACSHA2', 512),
    iterations => 5000,
    output_len => 32
  );

  my $salt_b64 = encode_base64 ($salt, "");

  my $key = $kdf->PBKDF2 ($salt_b64, $word);

  my $iv_bin = pack ("H*", $iv);

  my $cipher = Crypt::CBC->new ({
    key         => $key,
    cipher      => "Crypt::Rijndael",
    iv          => $iv_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "none"
  });

  my $pt = "";

  if (! defined ($ct))
  {
    $pt = "[{\"type\":\"HD Key Tree\",\"data\":{\"mnemonic\":\"ocean hidden kidney famous rich season gloom husband spring convince attitude boy\",\"numberOfAccounts\":1,\"hdPath\":\"m/44'/60'/0'/0\"}}]";
  }
  else
  {
    $pt = $cipher->decrypt (pack ("H*", $ct));

    if ($pt =~ m/^[ -~]*$/) # is_valid_printable_32 ()
    {
      # ok
    }
    else
    {
      $pt = ""; # fake
    }
  }

  my $ct1 = substr ($cipher->encrypt ($pt), 0, 32);

  my $hash = sprintf ('$metamaskMobile$%s$%s$%s', $salt_b64, $iv, encode_base64 ($ct1, ""));

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 16) eq '$metamaskMobile$';

  my (undef, $signature, $salt, $iv, $ct) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $iv;
  return unless defined $ct;

  my $salt_b64 = decode_base64 ($salt);
  my $iv_bin   = pack ("H*", $iv);
  my $ct_bin   = decode_base64 ($ct);

  return unless length $salt_b64 == 16;
  return unless length $iv_bin   == 16;
  return unless length $ct_bin   == 32;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt_b64, $iv, unpack ("H*", $ct_bin));

  return ($new_hash, $word);
}

1;
