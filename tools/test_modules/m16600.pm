#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA  qw (sha256);
use Crypt::CBC;

sub module_constraints { [[0, 256], [-1, -1], [0, 55], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word      = shift;
  my $iv        = shift || random_hex_string (32);
  my $salt_type = shift || 1;
  my $plain_bin = shift;

  if ($salt_type ne "1") { die "currently only salt_type 1 supported\n"; }

  my $key_bin = sha256 (sha256 ($word));

  my $iv_bin = pack ("H*", $iv);

  my $cipher = Crypt::CBC->new ({
    key         => $key_bin,
    cipher      => "Crypt::Rijndael",
    iv          => $iv_bin,
    literal_key => 1,
    header      => "none",
    keysize     => 32,
    padding     => "null",
  });

  if (defined $plain_bin)
  {
    my $encrypted_bin = pack ("H*", $plain_bin);

    my $test = $cipher->decrypt ($encrypted_bin);

    if ($test =~ /^[0-9a-f]+$/)
    {
      $plain_bin = $test;
    }
    else
    {
      $plain_bin = "\xff" x 16;
    }
  }
  else
  {
    my $plain = "30313233343536373839616263646566";

    $plain_bin = pack ("H*", $plain);
  }

  my $encrypted_bin = $cipher->encrypt ($plain_bin);

  my $encrypted = unpack ("H*", $encrypted_bin);

  my $hash = sprintf ("\$electrum\$%d*%s*%s", $salt_type, $iv, $encrypted);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($hash, $word) = split (':', $line);

  return unless defined $hash;
  return unless defined $word;

  my @data = split (/\*/, $hash);

  return unless scalar @data == 3;

  my ($mode, $iv, $encrypted) = @data;

  my (undef, $signature, $salt_type) = split ('\$', $mode);

  return unless ($signature eq "electrum");

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $iv, $salt_type, $encrypted);

  return ($new_hash, $word);
}

sub get_random_jwt_salt
{
  my @hashes =
  (
    "HS256",
    #"HS384", #this is support in hashcat, but commented out here to prevent mixed hash output files in single mode
    #"HS512", #this is support in hashcat, but commented out here to prevent mixed hash output files in single mode
    #"RS256", #not supported by hashcat
    #"RS384",
    #"RS512",
    #"PS256",
    #"PS384",
    #"PS512",
    #"ES256",
    #"ES384",
    #"ES512",
  );

  my $rnd = random_number (0, scalar @hashes - 1);

  my $hash = $hashes[$rnd];

  my $header =
  {
    "alg" => $hash
  };

  my $random_key = random_number (1, 100000000);
  my $random_val = random_number (1, 100000000);

  my $payload =
  {
    $random_key => $random_val
  };

  my $header_json    = encode_json ($header);
  my $payload_json   = encode_json ($payload);

  my $header_base64  = encode_base64url ($header_json, "");
  my $payload_base64 = encode_base64url ($payload_json, "");

  return $header_base64 . "." . $payload_base64;
}

1;